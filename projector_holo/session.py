"""Persistent fan session — discovery + TCP control connection + background
heartbeat thread, mirroring how the SpinDisplay Windows app maintains its
link in the captured pcap.

Why a session and not just FanClient? FanClient is one-shot (connect, send,
close). The fan rate-limits discovery (~1 reply per 3 seconds) so doing a
fresh connect for every API request is slow and flaky. The session does
discovery once at startup, keeps the TCP socket open, and pulses a
heartbeat every ~2s so the fan never closes us out.

Concurrency model: a single :class:`threading.Lock` serialises every
write+read pair on the socket so the background heartbeat and an inbound
PLAY/STOP from the web tier can't race. PLAY and STOP each drain their
own 7-byte ACK inside that critical section so the next heartbeat sees a
clean stream.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .client import (
    BRIGHTNESS_MAX_GUESSED,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DISCOVERY_PORT,
    DISCOVERY_REPLY_PORT,
    FanError,
    OP_DISCOVERY,
    OP_HEARTBEAT,
    OP_PLAY,
    OP_STOP,
    STATE_PLAYING,
    STATE_STOPPED,
    build_frame,
    op_brightness,
)

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL_S = 2.0   # match the captured Windows-app cadence
RECONNECT_BACKOFF_S = 4.0
DISCOVERY_RETRIES = 3
# Radio is noisy under rt2800usb; ping RTT swings 7-420 ms. Be generous.
SOCKET_TIMEOUT_S = 6.0


@dataclass
class FanState:
    connected: bool = False
    state_byte: int = 0
    last_update_at: float = 0.0
    last_error: str = ""
    discovery_payload_hex: str = ""

    @property
    def state(self) -> str:
        if not self.connected:
            return "DISCONNECTED"
        if self.state_byte == STATE_PLAYING:
            return "PLAYING"
        if self.state_byte == STATE_STOPPED:
            return "STOPPED"
        return f"UNKNOWN(0x{self.state_byte:02X})"

    def to_dict(self) -> dict:
        return {
            "connected": self.connected,
            "state_byte": self.state_byte,
            "state": self.state,
            "last_update_age_s": (time.time() - self.last_update_at) if self.last_update_at else None,
            "last_error": self.last_error,
            "discovery_hex": self.discovery_payload_hex,
        }


class FanSession:
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._state = FanState()
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------- lifecycle -------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, name="fan-session", daemon=True)
        self._thread.start()
        logger.info("FanSession started")

    def shutdown(self) -> None:
        self._stop_evt.set()
        # unblock recv in the worker
        with self._lock:
            sock = self._sock
            self._sock = None
            self._state.connected = False
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        logger.info("FanSession shut down")

    # ------------- public commands -------------

    @property
    def state(self) -> FanState:
        return self._state

    def play(self) -> dict:
        ack = self._send_and_ack(OP_PLAY, "PLAY")
        return {"ok": True, "action": "PLAY", "ack_hex": ack.hex()}

    def stop(self) -> dict:
        ack = self._send_and_ack(OP_STOP, "STOP")
        return {"ok": True, "action": "STOP", "ack_hex": ack.hex()}

    def set_brightness(self, level: int) -> dict:
        """Set fan brightness to absolute level. Verified for level 2-4 only
        — anything above is best-effort until we capture the full slider
        range. Range upper-clipped at BRIGHTNESS_MAX_GUESSED to avoid
        sending values the firmware might interpret unpredictably."""
        if not 0 <= level <= BRIGHTNESS_MAX_GUESSED:
            raise FanError(f"brightness level {level} out of range 0..{BRIGHTNESS_MAX_GUESSED}")
        ack = self._send_and_ack(op_brightness(level), f"BRIGHTNESS={level}")
        return {"ok": True, "action": "BRIGHTNESS", "level": level, "ack_hex": ack.hex()}

    def request_device_info(self) -> bytes:
        """Send a cmd 0x12 query and return the raw 448-byte device-info payload.

        WARNING: the payload contains the home-WiFi PSK in plaintext. The
        caller is responsible for redacting it before showing it to anyone
        — `projector_holo.device_info.parse_device_info()` does that. Do
        NOT cache the raw payload anywhere persistent.
        """
        query = build_frame(0x12)
        frame = self._send_and_ack(query, "DEVICE_INFO")
        # frame layout: [0x68][0x12][len_LE16][payload][crc_LE16]
        if len(frame) < 6 or frame[1] != 0x12:
            raise FanError(f"unexpected device-info frame: {frame[:8].hex()}")
        plen = frame[2] | (frame[3] << 8)
        return frame[4 : 4 + plen]

    # ------------- send/recv helpers -------------

    def _send_and_ack(self, frame: bytes, label: str) -> bytes:
        with self._lock:
            if not self._state.connected or self._sock is None:
                raise FanError(f"fan not connected ({self._state.last_error or 'session inactive'})")
            try:
                self._sock.settimeout(SOCKET_TIMEOUT_S)
                self._sock.sendall(frame)
                ack = self._recv_frame()
            except (OSError, socket.timeout) as e:
                self._mark_disconnected(f"{label} failed: {e}")
                raise FanError(f"{label} failed: {e}") from e
            logger.debug("%s ack: %s", label, ack.hex())
            return ack

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the socket. MUST be called inside the lock."""
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed by peer")
            buf += chunk
        return buf

    def _recv_frame(self) -> bytes:
        """Read one complete 0x68-protocol frame, draining and applying any
        async `cmd 0x35` state-push events the fan sends. Returns the next
        non-push frame.

        Frame layout: [magic 0x68][cmd 1B][len 2B LE][payload][crc 2B LE].
        Total length = 6 + payload_len.
        """
        assert self._sock is not None
        while True:
            # 4-byte header tells us how much more to read
            header = self._recv_exact(4)
            if header[0] != 0x68:
                raise OSError(f"out-of-frame byte: {header.hex()}")
            cmd = header[1]
            payload_len = header[2] | (header[3] << 8)
            tail = self._recv_exact(payload_len + 2)  # payload + 2-byte CRC
            frame = header + tail
            if cmd == 0x35:
                # async state-change push — apply and keep reading.
                if payload_len >= 2:
                    # Payload format from pcap: [channel:1B][state:1B] —
                    # state=0x00 maps to STOPPED-ish, 0x01 to PLAYING-ish.
                    # The heartbeat state byte is the authoritative source,
                    # so just log this and loop.
                    logger.debug("0x35 push (ignored): %s", frame.hex())
                continue
            return frame

    def _mark_disconnected(self, reason: str) -> None:
        self._state.connected = False
        self._state.last_error = reason
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------- background loop -------------

    def _run(self) -> None:
        while not self._stop_evt.is_set():
            # 1. ensure we're connected
            connected = False
            with self._lock:
                connected = self._state.connected and self._sock is not None
            if not connected:
                try:
                    self._connect_once()
                except Exception as e:
                    self._state.last_error = str(e)
                    logger.warning("connect failed: %s", e)
                    self._stop_evt.wait(RECONNECT_BACKOFF_S)
                    continue

            # 2. send heartbeat, update state byte
            try:
                with self._lock:
                    if self._sock is None or not self._state.connected:
                        continue
                    self._sock.settimeout(SOCKET_TIMEOUT_S)
                    self._sock.sendall(OP_HEARTBEAT)
                    reply = self._recv_frame()
                if reply[:2] == b"\x68\x14":
                    self._state.state_byte = reply[4]
                    self._state.last_update_at = time.time()
                    self._state.last_error = ""
                else:
                    self._state.last_error = f"unexpected HB reply: {reply.hex()}"
                    logger.warning(self._state.last_error)
            except (OSError, socket.timeout) as e:
                self._mark_disconnected(f"heartbeat: {e}")
                logger.info("heartbeat failed, will reconnect: %s", e)
                continue

            self._stop_evt.wait(HEARTBEAT_INTERVAL_S)

    def _connect_once(self) -> None:
        """Establish a working session: try TCP-probe first, only do
        discovery if the probe fails.

        Rationale: the fan rate-limits discovery (~1 reply per 3s) but
        once a client has discovered, it stays "remembered" for some
        window where bare TCP connections + heartbeats work fine. So we
        try the fast path first."""
        for need_discovery in (False, True):
            if need_discovery:
                try:
                    payload = self._do_discovery()
                    with self._lock:
                        self._state.discovery_payload_hex = payload.hex()
                except FanError as e:
                    logger.info("discovery failed, will still try TCP probe: %s", e)
            try:
                self._tcp_connect_with_probe()
                return
            except FanError as e:
                logger.info("TCP probe failed (need_discovery=%s): %s", need_discovery, e)
                if need_discovery:
                    raise

    def _tcp_connect_with_probe(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT_S)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            s.connect((self.host, self.port))
            s.sendall(OP_HEARTBEAT)
            # read using the same frame reader so 0x35 pushes don't desync.
            self._sock = s  # temp-bind for _recv_frame() helper
            try:
                buf = self._recv_frame()
            finally:
                self._sock = None  # we re-bind below under the lock
            if buf[:2] != b"\x68\x14":
                s.close()
                raise FanError(f"probe got unexpected reply: {buf.hex()}")
        except (OSError, socket.timeout) as e:
            s.close()
            raise FanError(f"TCP probe failed: {e}") from e

        with self._lock:
            self._sock = s
            self._state.connected = True
            self._state.state_byte = buf[4]
            self._state.last_update_at = time.time()
            self._state.last_error = ""
        logger.info("fan session up: %s:%s state=0x%02X", self.host, self.port, buf[4])

    def _do_discovery(self) -> bytes:
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("", DISCOVERY_REPLY_PORT))
        except OSError as e:
            listener.close()
            raise FanError(f"could not bind {DISCOVERY_REPLY_PORT}: {e}") from e
        listener.settimeout(SOCKET_TIMEOUT_S)
        bcast = self.host.rsplit(".", 1)[0] + ".255"
        try:
            for attempt in range(DISCOVERY_RETRIES):
                if self._stop_evt.is_set():
                    raise FanError("shutdown requested during discovery")
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                try:
                    udp.sendto(OP_DISCOVERY, (self.host, DISCOVERY_PORT))
                    try:
                        udp.sendto(OP_DISCOVERY, (bcast, DISCOVERY_PORT))
                    except OSError:
                        pass
                finally:
                    udp.close()
                try:
                    data, addr = listener.recvfrom(4096)
                    if len(data) >= 4 and data[0] == 0x68 and data[1] == 0x01:
                        logger.debug("discovery reply from %s: %s", addr, data.hex())
                        return data
                except socket.timeout:
                    self._stop_evt.wait(2.0)
                    continue
            raise FanError("discovery: no reply after retries")
        finally:
            listener.close()
