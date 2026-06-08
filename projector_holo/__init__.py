"""Spin Display F56 control client.

Public surface:
    FanClient        — one-shot TCP control client (TCP 50110, `0x68` protocol)
    FanSession       — persistent session with background heartbeat thread
    FanError         — raised on connection / write failures
    OP_PLAY/OP_STOP  — verified frames for cmd 0x17
    op_brightness    — frame builder for cmd 0x13 (verified for level 2-4)
    build_frame      — generic `0x68`-protocol frame builder
    parse_device_info — REDACTING parser for the cmd 0x12 reply

File upload (M2), file-select (M1 finish), TTS+BT speaker (M3), and the
agentic face (M4) are not yet wired — see CLAUDE.md.
"""

from .client import (
    BRIGHTNESS_MAX_GUESSED,
    BRIGHTNESS_MAX_OBSERVED,
    BRIGHTNESS_MIN_OBSERVED,
    FanClient,
    FanError,
    OP_PLAY,
    OP_STOP,
    STATE_PLAYING,
    STATE_STOPPED,
    build_frame,
    op_brightness,
)
from .device_info import DeviceInfo, parse_device_info
from .session import FanSession, FanState
from . import device_info, ftlv, udp_protocol

__all__ = [
    "FanClient", "FanError", "OP_PLAY", "OP_STOP",
    "STATE_PLAYING", "STATE_STOPPED",
    "FanSession", "FanState",
    "build_frame", "op_brightness",
    "BRIGHTNESS_MIN_OBSERVED", "BRIGHTNESS_MAX_OBSERVED", "BRIGHTNESS_MAX_GUESSED",
    "DeviceInfo", "parse_device_info",
    "device_info", "udp_protocol", "ftlv",
]
__version__ = "0.4.0"
