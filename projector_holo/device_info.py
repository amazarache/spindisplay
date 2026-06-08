"""Decode the fan's cmd 0x12 device-info reply — WITH CREDENTIAL REDACTION.

The 448-byte payload contains the fan MAC, model string ("F56"), some
firmware/config bytes, and four credential slots:

  - SoftAP SSID  @ 0x58 (null-terminated, ~25-byte slot)
  - SoftAP PSK   @ 0x71 (null-terminated, ~25-byte slot)
  - Home WiFi SSID @ 0x8A (null-terminated, ~33-byte slot)
  - Home WiFi PSK  @ 0xAB (null-terminated, ~33-byte slot)

The home WiFi PSK is the user's actual home network password in
plaintext. Any client on the F56's SoftAP can read it via this opcode.

This parser intentionally does NOT return the credential strings — only
booleans indicating whether each slot is populated, plus the MAC, model,
firmware bytes, and a SHA-256 of the full payload (so different fan
revisions can be told apart in logs without ever serialising the
sensitive bytes). Use only `parse_device_info()` in webapp/UI code.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

# Verified offsets from fan3_deviceinfo.pcap (2026-06-08):
_OFF_MAC = 0x08
_OFF_MODEL = 0x0E
_OFF_FIRMWARE = 0x40
_OFF_SOFTAP_SSID = 0x58
_OFF_SOFTAP_PSK = 0x71
_OFF_HOME_SSID = 0x8A
_OFF_HOME_PSK = 0xAB


@dataclass
class DeviceInfo:
    """Redacted view of the fan's device-info blob.

    Never includes SSID strings or PSKs. Callers wanting to confirm a
    specific configuration is present can check the booleans; if they
    need the actual values, they must read the raw payload themselves
    and accept the security implications.
    """

    mac: str
    model: str
    firmware_hex: str  # 12 bytes after offset 0x40 — opaque, hex-dumped
    has_softap_config: bool
    has_home_wifi_config: bool
    payload_sha256: str
    payload_len: int


def _read_cstr(buf: bytes, off: int, max_len: int) -> str:
    """Read a null-terminated string from buf at off, capped at max_len bytes."""
    end = buf.find(b"\x00", off, off + max_len)
    if end == -1:
        end = off + max_len
    chunk = buf[off:end]
    # only return as plain string if it's all printable ASCII; otherwise empty
    try:
        s = chunk.decode("ascii")
        if all(32 <= ord(c) < 127 for c in s):
            return s
    except UnicodeDecodeError:
        pass
    return ""


def parse_device_info(payload: bytes) -> DeviceInfo:
    """Parse a cmd 0x12 reply payload into a redacted DeviceInfo.

    Raises ValueError if the payload is too short to be a valid reply.
    Never returns SSID strings or PSKs.
    """
    if len(payload) < _OFF_HOME_PSK + 1:
        raise ValueError(f"device-info payload too short ({len(payload)} bytes)")

    mac_bytes = payload[_OFF_MAC : _OFF_MAC + 6]
    mac = ":".join(f"{b:02X}" for b in mac_bytes)
    model = _read_cstr(payload, _OFF_MODEL, 32)
    firmware_hex = payload[_OFF_FIRMWARE : _OFF_FIRMWARE + 12].hex()

    # Don't keep the SSIDs/PSKs — just check whether the first byte of
    # each slot is non-zero (a populated SSID starts with an ASCII char).
    has_softap = payload[_OFF_SOFTAP_SSID] != 0
    has_home = payload[_OFF_HOME_SSID] != 0

    return DeviceInfo(
        mac=mac,
        model=model,
        firmware_hex=firmware_hex,
        has_softap_config=has_softap,
        has_home_wifi_config=has_home,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_len=len(payload),
    )


def to_dict(info: DeviceInfo) -> dict:
    """Plain-dict view, safe to JSON-serialise to a client."""
    return asdict(info)
