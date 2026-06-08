# spindisplay — Open Control for the Spin Display F56

Host-side control software for the **Spin Display F56** holographic LED
fan (a.k.a. GIWOX / HOLOFAN / FTL LED — same firmware lineage, multiple
brand sleeves). Replaces the official iOS / Android / Windows app with
an open Python + FastAPI stack you can run on Linux against the fan's
SoftAP, build automation on top of, and extend.

The end goal: a Claude-driven holographic talking face. Today: playback
control, brightness, and a redacted device-info query, all verified live
against the fan over its real protocol.

## What works today

- ✅ **PLAY / STOP / STATUS** via the `0x68` protocol on TCP 50110
- ✅ **Brightness** control (cmd 0x13, wire range 0–5)
- ✅ **Device-info** query with credential redaction (cmd 0x12)
- ✅ Persistent **FanSession** with background heartbeat + auto-reconnect,
  rate-limit-aware UDP discovery, and a frame reader that handles async
  state-push notifications
- ✅ Single-page web UI on `http://127.0.0.1:8765/holo/`
- ✅ CLI: `python -m projector_holo {probe,status,play,stop}`

## What's still blocked

- ⏳ **M1 — Expression switcher**: file-select opcode is not yet
  identified. Cmd 0x31's 362-byte reply turned out to be a paired-device
  list, not a file list — SD enumeration uses some other opcode.
- ⏳ **M2 — Content upload**: FTLV header decoded and round-trips, but
  the per-frame pixel geometry is still unknown (captured frames are
  130× smaller than the naive radial-slice geometry would suggest).
- ⏳ **M3 — Voice**: TTS pipeline + Bluetooth speaker pairing not wired.
- ⏳ **M4 — Agentic face**: blocked on M2.

Each is tracked with reproducible next steps in the project's internal notes.

## Quick start

```bash
# Clone and install
git clone https://github.com/amazarache/spindisplay.git
cd spindisplay
python3 -m venv .venv
.venv/bin/pip install -e .

# Join your F56's SoftAP. The SSID is printed on the device, default
# PSK on stock firmware is 12345678. The fan IP is 10.10.10.1.
# (On NetworkManager-based Linux, a user-scoped `save no` profile is
#  the safe way to do this without touching system configuration.)

# Run the webapp
.venv/bin/uvicorn webapp:app --host 127.0.0.1 --port 8765

# Open the UI
xdg-open http://127.0.0.1:8765/holo/
```

### CLI

```bash
.venv/bin/python -m projector_holo probe   # TCP 50110 reachability
.venv/bin/python -m projector_holo status  # heartbeat + state byte
.venv/bin/python -m projector_holo play
.venv/bin/python -m projector_holo stop
```

### HTTP API

| Method | Path                       | Purpose                          |
|--------|----------------------------|----------------------------------|
| GET    | `/holo/api/probe`          | TCP reachability check           |
| GET    | `/holo/api/status`         | Current state from heartbeat     |
| POST   | `/holo/api/play`           | Start playback                   |
| POST   | `/holo/api/stop`           | Stop playback                    |
| POST   | `/holo/api/brightness`     | Body: `{"level": 0..5}`          |
| GET    | `/holo/api/device_info`    | MAC, model, firmware (REDACTED)  |

Endpoints for upcoming milestones (`/api/files`, `/api/play_file`,
`/api/upload`, `/api/speak`, `/api/chat`) return HTTP 501 with a
`phase` + `blocked_on` JSON body describing what's missing.

## Protocol summary

Every frame on TCP 50110 has the shape:

```
[magic=0x68][cmd 1B][len_LE16][payload][crc16-modbus_LE16]
```

A UDP discovery broadcast on port 50100 (with a 45-byte reply on UDP
50105) is a prerequisite — without it, the fan accepts the TCP handshake
but immediately closes the socket.

Verified opcodes:

| Cmd  | Direction | Meaning                                                  |
|------|-----------|----------------------------------------------------------|
| 0x00 | →fan UDP  | Discovery probe                                          |
| 0x01 | ←fan UDP  | Discovery reply (model + MAC + client IP)                |
| 0x10 | bidir     | Login / hello                                            |
| 0x11 | bidir     | Version query                                            |
| 0x12 | bidir     | Device-info dump — **leaks home WiFi PSK** (see below)   |
| 0x13 | bidir     | Brightness setter, 1-byte level **0–5**                  |
| 0x14 | bidir     | Heartbeat (state byte 0x28=STOPPED, 0x29=PLAYING)        |
| 0x17 | bidir     | Playback control (`01`=PLAY, `00`=STOP)                  |
| 0x21 | bidir     | Date/time sync (8-byte BCD-ish payload)                  |
| 0x31 | bidir     | Paired-device list                                       |
| 0x35 | async     | State-change push                                        |

Full opcode catalogue, frame examples, and the APK reverse-engineering
notes are tracked privately and not part of this public repo.

## Security note

The fan's cmd 0x12 device-info reply embeds the user's **home WiFi SSID
and PSK in plaintext** at fixed offsets (0x8A and 0xAB respectively).
Any client on the fan's open SoftAP can read them.

This repository's parser
([`projector_holo/device_info.py`](projector_holo/device_info.py))
intentionally drops the credential fields and returns only MAC, model,
firmware bytes, and "has-config" booleans. The raw 0x12 payload is
never logged or returned over HTTP.

If you work on this project:

- **Do not commit packet captures.** The `.gitignore` blocks `*.pcap`,
  `*.pcapng`, `*.etl`, `captures/`, and `pcaps/`. Work in a scratch dir
  like `/tmp/spindisplay/`.
- **Rotate your home WiFi password** if you've previously configured the
  fan to join it via the SpinDisplay app.

## Architecture

| File                            | Role                                      |
|---------------------------------|-------------------------------------------|
| `projector_holo/client.py`      | TCP client, opcode constants, CRC-16-MODBUS, frame builder |
| `projector_holo/session.py`     | Persistent session, background heartbeat, async-push-aware reader |
| `projector_holo/device_info.py` | REDACTING cmd 0x12 parser                 |
| `projector_holo/ftlv.py`        | FTLV file-format scaffold (M2 in progress)|
| `projector_holo/udp_protocol.py`| APK-derived reference opcode catalog      |
| `projector_holo/__main__.py`    | CLI entry point                           |
| `webapp.py`                     | FastAPI app on `127.0.0.1:8765`           |
| `static/index.html`             | Single-page control UI                    |

## Roadmap

| Milestone | Description                                                   | Status            |
|-----------|---------------------------------------------------------------|-------------------|
| M0        | PLAY/STOP/STATUS + brightness + redacted device-info          | ✅ Shipped         |
| M1        | SD-card file enumeration + file-select (expression switcher)  | 🔍 Needs pcap      |
| M2        | Content upload via FTLV transcoder                            | ⏳ Body format TBD |
| M3        | TTS over Bluetooth speaker                                    | ⏳ Not started     |
| M4        | Claude-driven talking holographic face                        | ⏳ Blocked on M2   |

## License

MIT. See `LICENSE` (or `pyproject.toml`).

## Disclaimer

This is unofficial reverse-engineering done for personal interoperability
and educational purposes. The Spin Display F56 firmware and the
"SpinDisplay" app are property of their respective owners (FTL LED /
GIWOX / HOLOFAN family). All testing in this repo is against a fan the
author owns, on the fan's own SoftAP. Use at your own risk.
