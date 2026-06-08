"""SpinDisplay UDP control protocol — reverse-engineered from the
3D Magic / SpinDisplay Android app (com.dmz.f20ad, version 2.0.1.8).

This is the proprietary "app-mode" protocol used when Third-Party Control
mode is DISABLED on the fan. It is mutually exclusive with the TCP-50200
``5B``-prefix opcode channel in `client.py`.

Frame format (verified by reading ``d.e.a.t.h.*`` and ``d.e.a.t.b.a`` in
the APK's classes.dex)::

    +------+------+--------+---------+----------+
    | 0x68 | cmd  | len LE | payload | CRC16 LE |
    | 1B   | 1B   | 2B     | N B     | 2B       |
    +------+------+--------+---------+----------+

- Magic byte is ``0x68`` (ASCII ``'h'``), NOT ``0x5B`` as the third-party
  channel uses.
- ``len`` is the LITTLE-ENDIAN u16 byte-length of the payload, exclusive
  of header and CRC.
- ``crc16`` is CRC-16-MODBUS (polynomial 0xA001, init 0xFFFF, reflected
  in/out, no final XOR) over magic + cmd + len + payload.

Transport:
- Fan listens for commands on **UDP port 50100**.
- Fan broadcasts its presence to clients on UDP port 50105 (clients bind
  there to discover fans). This is NOT enabled when Third-Party Control
  is on — the fan goes silent.

Command catalog (extracted by enumerating builder methods in
``com.dmz.f20ad.connect.UdpService`` and ``d.e.a.t.h``):

    cmd  builder signature              payload    function (best guess)
    ---  ----------------------------   --------   --------------------------
    0x02 (String<=8, int)             9 B        LOGIN (password + device-type)
    0x07 (int, String<=32, String<=64) 99 B      WIFI config (flag + SSID + PSK)
    0x12 ()                            0 B        Query (B-class)
    0x13 (int)                         1 B        Single-byte set (B-class)
    0x18 (int)                         2 B        Two-byte set (brightness?)
    0x20 (7 ints)                      7 B        TIMER schedule
    0x22 (int)                         1 B        Single-byte set
    0x23 (int, int)                    2 B        Two-byte set
    0x24 (int)                         1 B        Single-byte set
    0x31 ()                            0 B        Query / device-info ping
    0x32 (int, int)                    2 B        Two-byte set
    0x35 (int, int)                    2 B        Two-byte set
    0x36 (bytes)                       N B        RAW PAYLOAD wrapper (upload?)
    0x37 (int)                         1 B        Single-byte set

The semantics of most single/two-byte commands (brightness, rotation,
file-select, etc.) are not yet mapped — they would be by tracing where
each builder is *called* from in the activity/fragment classes.

Status on F56 with Third-Party Control mode ENABLED: silent (this
protocol is not active in TPC mode). On F56 with TPC mode DISABLED:
unverified — the user has only tested TPC-on so far. The protocol
implementation here is provided so we can probe it the moment TPC is
toggled off.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

UDP_CMD_PORT = 50100         # broadcast discovery (per APK)
UDP_DISCOVERY_PORT = 50105   # client listens here for fan replies
TCP_CONTROL_PORT = 50110     # **verified via pcap** — app's main control channel
MAGIC = 0x68

# Verified from pcap capture (2026-06-04): the SpinDisplay app polls the fan
# every ~2s with a 6-byte heartbeat `68 14 00 00 5c 40` over TCP 50110, and
# the fan replies with `68 14 01 00 XX <crc>` where XX is a state byte.
# The fan also pushes async state-change events to the client as
# `68 35 02 00 00 01 44 8f`.
CMD_HEARTBEAT = 0x14         # 6-byte empty req, 7-byte reply with 1-byte state
CMD_STATE_PUSH = 0x35        # fan→client unsolicited state notification

# Verified command IDs (see module docstring for semantics).
CMD_LOGIN = 0x02
CMD_WIFI_CONFIG = 0x07
CMD_QUERY_B = 0x12
CMD_QUERY_DEVICE_INFO = 0x31
CMD_TIMER_SCHEDULE = 0x20
CMD_RAW_WRAPPER = 0x36

# Device-type byte in the login frame; values match the strings extracted
# from UdpService.b() — "Android" -> 0, "Iphone" -> 1, "PC" -> 2.
DEVICE_TYPE_ANDROID = 0
DEVICE_TYPE_IPHONE = 1
DEVICE_TYPE_PC = 2


def crc16_modbus(data: bytes) -> int:
    """CRC-16-MODBUS (poly 0xA001, init 0xFFFF, reflected, no final XOR).

    Verified equivalent to the table-driven implementation in
    ``d/e/a/t/b.a([BII)I`` — the APK splits a single 16-bit CRC table
    into two 256-byte sub-tables but the algorithm reduces to the
    canonical Modbus polynomial.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ 0xA001) if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def build_frame(cmd: int, payload: bytes = b"") -> bytes:
    """Build a complete framed packet: magic + cmd + LE len + payload + LE CRC.

    Raises ValueError for cmd / payload size violations.
    """
    if not 0 <= cmd <= 0xFF:
        raise ValueError(f"cmd out of range: {cmd}")
    if len(payload) > 0xFFFF:
        raise ValueError(f"payload too large: {len(payload)} bytes")
    body = bytes([MAGIC, cmd]) + struct.pack("<H", len(payload)) + payload
    return body + struct.pack("<H", crc16_modbus(body))


def parse_frame(packet: bytes) -> tuple[int, bytes]:
    """Parse an incoming framed packet; return (cmd, payload).

    Validates magic, length consistency, and CRC. Raises ValueError on
    any check failure (untrusted peer — never silently accept).
    """
    if len(packet) < 6:
        raise ValueError(f"packet too short: {len(packet)} bytes")
    if packet[0] != MAGIC:
        raise ValueError(f"bad magic: 0x{packet[0]:02X} (expected 0x68)")
    cmd = packet[1]
    plen = struct.unpack("<H", packet[2:4])[0]
    if len(packet) != 4 + plen + 2:
        raise ValueError(
            f"length mismatch: header says {plen} payload bytes, "
            f"packet has {len(packet) - 6} payload bytes"
        )
    payload = packet[4 : 4 + plen]
    crc_observed = struct.unpack("<H", packet[4 + plen : 4 + plen + 2])[0]
    crc_computed = crc16_modbus(packet[: 4 + plen])
    if crc_observed != crc_computed:
        raise ValueError(
            f"CRC mismatch: packet says 0x{crc_observed:04X}, computed 0x{crc_computed:04X}"
        )
    return cmd, payload


def build_login(password: str = "", device_type: int = DEVICE_TYPE_PC) -> bytes:
    """Build the login (cmd 0x02) frame.

    Payload is exactly 9 bytes: 8 bytes UTF-8 of password (truncated /
    null-padded) + 1 byte device-type (one of DEVICE_TYPE_*).

    Default password is EMPTY (8 zero bytes) — the SpinDisplay Windows app's
    settings page shows the API password field blank on this F56, so the
    fan's UDP listener accepts empty-password logins. Pass an explicit
    password only if the user has set one in the app.
    """
    pwd_bytes = password.encode("utf-8")[:8].ljust(8, b"\x00")
    payload = pwd_bytes + bytes([device_type & 0xFF])
    return build_frame(CMD_LOGIN, payload)


def send_udp(host: str, payload: bytes, *, port: int = UDP_CMD_PORT, timeout: float = 2.0) -> Optional[bytes]:
    """Send a framed packet and return the reply, or None on timeout.

    The fan-mode protocol is request/reply — replies are framed packets
    in the same format. Returns None if no reply arrived within ``timeout``.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        try:
            data, _addr = s.recvfrom(4096)
            return data
        except socket.timeout:
            return None
    finally:
        s.close()


def listen_for_discovery(timeout: float = 10.0, *, port: int = UDP_DISCOVERY_PORT) -> list[tuple[bytes, tuple[str, int]]]:
    """Listen for fan broadcasts on the discovery port.

    Returns a list of (raw_packet, sender_addr) tuples. Empty if no
    broadcasts arrived in ``timeout`` seconds. NOTE: in Third-Party
    Control mode, fans do not broadcast — this returns []. Useful only
    after the user disables TPC.
    """
    import time

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", port))
    received = []
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            s.settimeout(max(0.1, deadline - time.time()))
            try:
                data, addr = s.recvfrom(4096)
                received.append((data, addr))
            except socket.timeout:
                break
    finally:
        s.close()
    return received
