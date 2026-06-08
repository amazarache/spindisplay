"""CLI entry point — `python -m projector_holo {play,stop,status,probe}`."""

from __future__ import annotations

import argparse
import logging
import sys

from .client import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    STATE_PLAYING,
    STATE_STOPPED,
    FanClient,
    FanError,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m projector_holo",
        description="Spin Display F56 PLAY/STOP control (TCP 50110, 0x68 protocol).",
    )
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"fan IP (default: {DEFAULT_HOST})")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"control port (default: {DEFAULT_PORT})")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="socket timeout in seconds")
    ap.add_argument("-v", "--verbose", action="store_true", help="DEBUG logging on stderr")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("play", help="send PLAY (68 17 01 00 01) over TCP 50110")
    sub.add_parser("stop", help="send STOP (68 17 01 00 00) over TCP 50110")
    sub.add_parser("status", help="send heartbeat and report fan state")
    sub.add_parser("probe", help="check whether TCP 50110 is reachable")

    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(message)s",
        stream=sys.stderr,
    )

    fan = FanClient(host=args.host, port=args.port, timeout=args.timeout)
    try:
        if args.cmd == "probe":
            if fan.reachable():
                print(f"{args.host}:{args.port} open")
                return 0
            print(f"{args.host}:{args.port} unreachable", file=sys.stderr)
            return 1

        if args.cmd == "play":
            with fan:
                fan.play()
            print("PLAY sent")
            return 0

        if args.cmd == "stop":
            with fan:
                fan.stop()
            print("STOP sent")
            return 0

        if args.cmd == "status":
            with fan:
                state = fan.heartbeat()
            label = {
                STATE_PLAYING: "PLAYING",
                STATE_STOPPED: "STOPPED",
            }.get(state, f"UNKNOWN(0x{state:02X})")
            print(f"state=0x{state:02X} ({label})")
            return 0 if state in (STATE_PLAYING, STATE_STOPPED) else 1

    except FanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
