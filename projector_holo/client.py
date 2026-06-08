"""TCP control client for the Spin Display F56 holographic LED fan.

The fan speaks a binary, request/response protocol on TCP port 50110
(the `0x68` framing — verified via a Windows-app pcap). Frames are:

    [magic=0x68][cmd 1B][len_LE16][payload][crc16-modbus_LE16]

Threat model: the fan is on a shared SoftAP with no authentication. We
treat it as an untrusted peer — bounded timeouts, capped recv, no
shell-interpolated values, no echoing fan bytes into a shell context.

WARNING: the fan's cmd 0x12 device-info reply contains the SoftAP PSK and
the home-WiFi PSK in plaintext. Any client on the SoftAP can read them.
Never log, return over HTTP, or commit the raw 0x12 payload.
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

DEFAULT_HOST = "10.10.10.1"
DEFAULT_PORT = 50110
DEFAULT_TIMEOUT = 3.0
MAX_REPLY_BYTES = 4096

# Discovery: UDP broadcast that MUST precede any TCP 50110 connection.
# Without it the fan accepts the TCP handshake but immediately closes the
# socket without replying to a heartbeat. Verified empirically on this F56.
DISCOVERY_PORT = 50100
DISCOVERY_REPLY_PORT = 50105
OP_DISCOVERY: bytes = bytes.fromhex("68 00 04 00 cb 0c 05 3c bb 67".replace(" ", ""))

# Pre-computed PLAY / STOP frames in the `0x68` protocol over TCP 50110,
# verified from a Windows SpinDisplay-app traffic capture (fan2.pcap).
# Cmd 0x17 — 1-byte payload: 0x01 = start, 0x00 = stop. CRC is CRC-16-MODBUS.
OP_PLAY: bytes = bytes.fromhex("68 17 01 00 01 d0 7d".replace(" ", ""))
OP_STOP: bytes = bytes.fromhex("68 17 01 00 00 11 bd".replace(" ", ""))
OP_HEARTBEAT: bytes = bytes.fromhex("68 14 00 00 5c 40".replace(" ", ""))

# Heartbeat reply byte semantics (state byte at offset 4 of the 7-byte reply):
STATE_STOPPED = 0x28
STATE_PLAYING = 0x29

# Brightness — cmd 0x13 with a 1-byte absolute level. Verified live
# (CLI sweep against fan, 2026-06-08): the fan accepts levels 0-5 and
# clamps anything above 5 to 5 (the fan echoes back the clamped value,
# not the value we sent, which is how we confirmed the ceiling).
CMD_BRIGHTNESS = 0x13
BRIGHTNESS_MIN_OBSERVED = 0x00
BRIGHTNESS_MAX_OBSERVED = 0x05
BRIGHTNESS_MAX_GUESSED = 0x05  # fan-side clamp; values above are no-ops


def _crc16_modbus(data: bytes) -> int:
    """CRC-16-MODBUS over `data` (poly 0xA001, init 0xFFFF, reflected, no XOR).

    Matches the CRC used by the F56's 0x68 framing and by the APK's
    `d.e.a.t.b.a` CRC class. Returns a 16-bit int; caller serialises LE.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def build_frame(cmd: int, payload: bytes = b"") -> bytes:
    """Build a `0x68`-protocol frame: magic, cmd, len_LE16, payload, crc_LE16."""
    if not 0 <= cmd <= 0xFF:
        raise ValueError(f"cmd must be 0..255, got {cmd}")
    if len(payload) > 0xFFFF:
        raise ValueError(f"payload too large: {len(payload)} bytes")
    header = bytes([0x68, cmd, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
    crc = _crc16_modbus(header + payload)
    return header + payload + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def op_brightness(level: int) -> bytes:
    """Build a brightness-set frame: `68 13 01 00 <level> <crc16_LE>`.

    Verified for level=0x03 → frame `68 13 01 00 03 50 8c` and level=0x04
    → frame `68 13 01 00 04 ...` (captured from SpinDisplay app traffic).
    Returns a 7-byte frame ready to send over TCP 50110.
    """
    if not 0 <= level <= 0xFF:
        raise ValueError(f"brightness level must be 0..255, got {level}")
    return build_frame(CMD_BRIGHTNESS, bytes([level]))

logger = logging.getLogger(__name__)


class FanError(RuntimeError):
    """The fan refused a connection, dropped the socket, or a write failed."""


class FanClient:
    """Minimal TCP control client for the Spin Display F56.

    Use as a context manager when issuing more than one command in close
    succession — the rt2800usb USB WiFi driver this project ships against
    crashes under burst reconnects, so we hold the socket open across
    commands rather than reopening per call.

    Single-shot use (no context manager) opens and closes per command and
    is fine for occasional control.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._discovered: bool = False

    def __enter__(self) -> "FanClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def discover(self, *, retries: int = 2) -> bytes:
        """Send the UDP discovery probe and wait for the fan's reply.

        The fan will NOT respond to a TCP control connection until it has
        seen a discovery broadcast from the client's IP — empirically the
        first TCP heartbeat after a cold start returns zero bytes (FIN)
        unless this is called first. Returns the fan's reply payload
        (cmd 0x01, contains model name + MAC + assigned client IP).

        The fan rate-limits discovery replies (~1 reply per ~3s on F56),
        so we retry up to ``retries`` times with backoff on timeout.
        """
        # Bind the listener BEFORE we send so we don't race the reply.
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("", DISCOVERY_REPLY_PORT))
        except OSError as e:
            listener.close()
            raise FanError(f"could not bind discovery-reply port {DISCOVERY_REPLY_PORT}: {e}") from e
        listener.settimeout(self.timeout)

        try:
            bcast = self.host.rsplit(".", 1)[0] + ".255"
            for attempt in range(retries + 1):
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                udp.sendto(OP_DISCOVERY, (self.host, DISCOVERY_PORT))
                try:
                    udp.sendto(OP_DISCOVERY, (bcast, DISCOVERY_PORT))
                except OSError:
                    pass
                udp.close()
                try:
                    data, addr = listener.recvfrom(4096)
                    if len(data) >= 4 and data[0] == 0x68 and data[1] == 0x01:
                        self._discovered = True
                        logger.debug("discovery reply from %s: %s", addr, data.hex())
                        return data
                    logger.debug("ignoring unexpected udp reply %s", data[:16].hex())
                except socket.timeout:
                    if attempt < retries:
                        # Fan rate-limits replies — back off and re-broadcast.
                        import time as _t
                        _t.sleep(2.0)
                        continue
            raise FanError("discovery: fan did not reply within timeout")
        finally:
            listener.close()

    def connect(self) -> None:
        if self._sock is not None:
            return
        if not self._discovered:
            self.discover()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            s.connect((self.host, self.port))
        except (OSError, socket.timeout) as e:
            s.close()
            raise FanError(
                f"cannot reach fan at {self.host}:{self.port}: {e}"
            ) from e
        self._sock = s
        logger.debug("connected to %s:%s", self.host, self.port)

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self._sock.close()
        except OSError:
            pass
        self._sock = None

    def _send(self, frame: bytes, *, expect_ack: bool = True) -> Optional[bytes]:
        if len(frame) > 1024:
            raise FanError("frame too large; refusing to send")
        opened_here = self._sock is None
        if opened_here:
            self.connect()
        assert self._sock is not None
        try:
            self._sock.sendall(frame)
        except (OSError, socket.timeout) as e:
            self.close()
            raise FanError(f"write failed: {e}") from e
        logger.debug("sent %s", frame.hex())

        ack = None
        if expect_ack:
            # The 0x68 protocol is strict request/response. After a PLAY/STOP
            # the fan echoes the same 7-byte frame back. We MUST drain it,
            # otherwise it sits in the socket buffer and corrupts the next
            # heartbeat read.
            try:
                self._sock.settimeout(self.timeout)
                ack = b""
                while len(ack) < 7:
                    chunk = self._sock.recv(7 - len(ack))
                    if not chunk:
                        break
                    ack += chunk
            except (OSError, socket.timeout):
                # Best-effort: missing ACK is logged but not fatal
                logger.debug("no ACK for frame %s", frame.hex())

        if opened_here:
            self.close()
        return ack

    def play(self) -> None:
        """Send the verified PLAY frame (`68 17 01 00 01 d0 7d`) over TCP 50110.

        Verified from Windows SpinDisplay app pcap (2026-06-04). The fan
        ACKs by echoing the same frame back. Heartbeat-reply state byte
        transitions from 0x28 (stopped) → 0x29 (playing).
        """
        self._send(OP_PLAY)

    def stop(self) -> None:
        """Send the verified STOP frame (`68 17 01 00 00 11 bd`) over TCP 50110.

        Verified from Windows SpinDisplay app pcap (2026-06-04). The fan
        ACKs by echoing the same frame back. Heartbeat-reply state byte
        transitions from 0x29 (playing) → 0x28 (stopped).
        """
        self._send(OP_STOP)

    def heartbeat(self) -> int:
        """Send a heartbeat and return the fan's 1-byte state.

        Returns the state byte from the fan's 7-byte reply
        (`68 14 01 00 STATE crc_lo crc_hi`). 0x28 = stopped, 0x29 = playing.
        Raises FanError on connection / framing failure.
        """
        opened_here = self._sock is None
        if opened_here:
            self.connect()
        assert self._sock is not None
        try:
            self._sock.sendall(OP_HEARTBEAT)
            reply = self._sock.recv(7)
        except (OSError, socket.timeout) as e:
            self.close()
            raise FanError(f"heartbeat failed: {e}") from e
        if len(reply) != 7 or reply[:2] != b"\x68\x14":
            self.close()
            raise FanError(f"unexpected heartbeat reply: {reply.hex()}")
        if opened_here:
            self.close()
        return reply[4]

    def reachable(self) -> bool:
        """True iff TCP port 50110 accepts a connection.

        Does not prove the listener implements the SpinDisplay protocol —
        only that the fan is on the network and accepting connections.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
            return True
        except (OSError, socket.timeout):
            return False
        finally:
            try:
                s.close()
            except OSError:
                pass
