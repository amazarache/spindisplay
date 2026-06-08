"""FastAPI control surface for the Spin Display F56.

Routes:
    GET  /holo/                — single-page control UI
    GET  /holo/api/status      — current fan state via heartbeat
    POST /holo/api/play        — send PLAY
    POST /holo/api/stop        — send STOP
    POST /holo/api/brightness  — set brightness level (0..15)
    GET  /holo/api/device_info — fan MAC, model, firmware (creds REDACTED)
    GET  /holo/api/probe       — TCP reachability check
    GET  /holo/healthz         — liveness probe

  Stubs for upcoming phases (return HTTP 501 Not Implemented):
    GET  /holo/api/files       — list SD-card content (M1)
    POST /holo/api/play_file   — play file at index (M1)
    POST /holo/api/upload      — upload GIF/MP4 (M2, needs FTLV transcoder)
    POST /holo/api/speak       — TTS → BT speaker + lip-sync face (M3)
    POST /holo/api/chat        — Claude-driven agentic face (M4)

Run with:
    .venv/bin/uvicorn webapp:app --host 127.0.0.1 --port 8000

Then open http://localhost:8000/holo/ in a browser.

Security note: this binds 127.0.0.1 only — no external exposure. The fan
itself is treated as an untrusted peer per the project's OWASP standard:
bounded timeouts on every call, no echo of fan bytes into the HTML, no
shell-interpolated values anywhere in the request handlers.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from projector_holo.client import (
    BRIGHTNESS_MAX_GUESSED,
    BRIGHTNESS_MAX_OBSERVED,
    BRIGHTNESS_MIN_OBSERVED,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    FanError,
)
from projector_holo.device_info import parse_device_info, to_dict as device_info_to_dict
from projector_holo.session import FanSession

STATIC_DIR = Path(__file__).parent / "static"

# Singleton session: discovers ONCE at startup, holds the TCP socket,
# runs a 2-second heartbeat in a background thread, reconnects on any
# failure. Every API request shares this connection.
fan_session = FanSession(host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT)


@asynccontextmanager
async def lifespan(app: FastAPI):
    fan_session.start()
    try:
        yield
    finally:
        fan_session.shutdown()


app = FastAPI(
    title="Spin Display F56 Control",
    description="HTTP control surface for the holographic LED fan.",
    version="0.4.0",
    docs_url="/holo/api/docs",
    redoc_url=None,
    openapi_url="/holo/api/openapi.json",
    lifespan=lifespan,
)


class StatusOut(BaseModel):
    state_byte: int
    state: str
    reachable: bool
    last_update_age_s: Optional[float] = None
    last_error: str = ""


class ActionOut(BaseModel):
    ok: bool
    action: str
    ack_hex: str = ""


@app.get("/holo/", include_in_schema=False)
def serve_index() -> FileResponse:
    index = STATIC_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=500, detail="UI not built; static/index.html missing")
    return FileResponse(index)


@app.get("/holo/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"ok": True})


@app.get("/holo/api/probe")
def api_probe() -> JSONResponse:
    st = fan_session.state
    return JSONResponse({
        "reachable": st.connected,
        "host": fan_session.host,
        "port": fan_session.port,
        "last_error": st.last_error,
    })


@app.get("/holo/api/status", response_model=StatusOut)
def api_status() -> StatusOut:
    st = fan_session.state
    return StatusOut(
        state_byte=st.state_byte,
        state=st.state,
        reachable=st.connected,
        last_update_age_s=(None if st.last_update_at == 0 else (st.to_dict()["last_update_age_s"])),
        last_error=st.last_error,
    )


@app.post("/holo/api/play", response_model=ActionOut)
def api_play() -> ActionOut:
    try:
        r = fan_session.play()
    except FanError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return ActionOut(ok=True, action="PLAY", ack_hex=r.get("ack_hex", ""))


@app.post("/holo/api/stop", response_model=ActionOut)
def api_stop() -> ActionOut:
    try:
        r = fan_session.stop()
    except FanError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return ActionOut(ok=True, action="STOP", ack_hex=r.get("ack_hex", ""))


# ----------------------------------------------------------------------------
# Stubs for upcoming milestones. Every stub returns 501 Not Implemented with a
# `phase` and `blocked_on` field so the frontend can render meaningful
# "coming soon" affordances without having to enumerate features here.
# ----------------------------------------------------------------------------


def _not_implemented(phase: str, blocked_on: str) -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={
            "ok": False,
            "phase": phase,
            "blocked_on": blocked_on,
            "detail": f"{phase}: not implemented yet — {blocked_on}",
        },
    )


class PlayFileIn(BaseModel):
    index: int = Field(..., ge=0, le=255, description="File index 0..255")


class BrightnessIn(BaseModel):
    level: int = Field(
        ...,
        ge=0,
        le=BRIGHTNESS_MAX_GUESSED,
        description=(
            f"Absolute brightness 0..{BRIGHTNESS_MAX_GUESSED}. Verified live "
            f"only for {BRIGHTNESS_MIN_OBSERVED}..{BRIGHTNESS_MAX_OBSERVED}; "
            "out-of-range values are clipped server-side."
        ),
    )


class SpeakIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000, description="text to speak (lip-sync + audio)")
    voice: str = Field("default", description="TTS voice id; default = local Piper")


class ChatIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000, description="user message to the agent")


@app.get("/holo/api/files")
def api_files_list() -> JSONResponse:
    return _not_implemented(
        phase="M1 / expression switcher",
        blocked_on="need cmd 0x31 device-info parser; the 368-byte reply shape from pcap is captured but not yet decoded",
    )


@app.post("/holo/api/play_file")
def api_play_file(req: PlayFileIn) -> JSONResponse:
    return _not_implemented(
        phase="M1 / expression switcher",
        blocked_on=(
            f"index={req.index} unmapped; need to identify the file-select opcode (no candidate 5B 01 NN value worked, "
            "and the 0x68 catalog hasn't been disambiguated)"
        ),
    )


@app.post("/holo/api/brightness", response_model=ActionOut)
def api_brightness(req: BrightnessIn) -> ActionOut:
    """Set absolute brightness via cmd 0x13.

    Verified live for levels 2-4 (slider drag in SpinDisplay app, 2026-06-08).
    The 0-15 range is a 4-bit-field guess; values above 4 may either map
    to brighter levels or be no-ops until we capture the full slider sweep.
    """
    try:
        r = fan_session.set_brightness(req.level)
    except FanError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return ActionOut(ok=True, action=f"BRIGHTNESS={req.level}", ack_hex=r.get("ack_hex", ""))


@app.get("/holo/api/device_info")
def api_device_info() -> JSONResponse:
    """Return the fan's REDACTED device info.

    Sends a cmd 0x12 query, drops the raw payload immediately after
    parsing, and returns only MAC + model + firmware-bytes + populated-
    config booleans. The raw payload contains the user's home WiFi
    password in plaintext — see projector_holo/device_info.py.
    """
    try:
        payload = fan_session.request_device_info()
        info = parse_device_info(payload)
    except FanError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    # raw payload goes out of scope here; never serialised
    return JSONResponse(device_info_to_dict(info))


@app.post("/holo/api/upload")
async def api_upload(file: UploadFile = File(...)) -> JSONResponse:
    # Drain the upload so the client connection isn't held open after the 501.
    body = await file.read()
    return _not_implemented(
        phase="M2 / content upload",
        blocked_on=(
            f"received {len(body)}B `{file.filename}` but FTLV transcoder not built; only header layout known "
            "(version, sizes, frame_count, framerate) — radial-slice rendering still TBD"
        ),
    )


@app.post("/holo/api/speak")
def api_speak(req: SpeakIn) -> JSONResponse:
    return _not_implemented(
        phase="M3 / voice",
        blocked_on=(
            f"text length={len(req.text)}, voice='{req.voice}'; TTS pipeline (Piper local or ElevenLabs cloud) "
            "not wired, BT speaker pairing to the fan not configured"
        ),
    )


@app.post("/holo/api/chat")
def api_chat(req: ChatIn) -> JSONResponse:
    return _not_implemented(
        phase="M4 / agentic face",
        blocked_on=(
            f"received {len(req.message)}-char message; Claude API client not wired, lip-sync renderer "
            "(phonemes → mouth-shapes → FTLV frames) blocked on M2"
        ),
    )
