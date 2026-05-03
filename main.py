#!/usr/bin/env python3
"""SentinelX command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from blocker import IPBlocker
from detector import PacketSniffer, SuspiciousDetector
from logger import AlertLogger
from scorer import ThreatScorer
from ui import BANNER, RichUI
from banner import show_logo

show_logo()

VERSION = "1.0"
APP_NAME = "SentinelX"
STATE_DIR = Path.home() / ".sentinelx"
PID_FILE = STATE_DIR / "sentinelx.pid"
STATE_FILE = STATE_DIR / "sentinelx_state.json"
DEFAULT_LOG_FILE = STATE_DIR / "alerts.jsonl"


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return True if geteuid is None else geteuid() == 0


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def write_runtime_state(args: argparse.Namespace) -> None:
    ensure_state_dir()
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    STATE_FILE.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "version": VERSION,
                "interface": args.interface,
                "threshold": args.threshold,
                "blocking": not args.no_block,
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def clear_runtime_state() -> None:
    for path in (PID_FILE, STATE_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def build_parser() -> argparse.ArgumentParser:
    examples = """
Examples:
  sentinelx start --interface eth0 --threshold 15
  sentinelx start --interface wlan0 --no-block
  sentinelx status
  sentinelx stop

Notes:
  - Run start with sudo/root privileges for packet capture.
  - IPS blocking uses iptables on Linux. On other systems, blocking is disabled.
  - Alerts are written as JSON Lines to ~/.sentinelx/alerts.jsonl by default.
"""
    parser = argparse.ArgumentParser(
        prog="sentinelx",
        description=(
            "SentinelX v1.0 - terminal IDS/IPS for real-time packet monitoring, "
            "threat scoring, alerting, and automatic malicious IP blocking."
        ),
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser(
        "start",
        help="Start real-time IDS/IPS monitoring.",
        description="Start SentinelX packet monitoring and live threat scoring.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  sentinelx start --interface eth0 --threshold 15",
    )
    start_parser.add_argument(
        "--interface",
        "-i",
        required=True,
        help="Network interface to monitor, for example eth0 or wlan0.",
    )
    start_parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        default=10,
        help="Threat score limit before an IP is blocked. Default: 10.",
    )
    start_parser.add_argument(
        "--no-block",
        action="store_true",
        help="Disable IPS blocking. Detection, scoring, UI, and logging remain active.",
    )
    start_parser.add_argument(
        "--log-file",
        default=str(DEFAULT_LOG_FILE),
        help="Alert log file path. Default: ~/.sentinelx/alerts.jsonl.",
    )

    subparsers.add_parser("stop", help="Stop a running SentinelX process.")
    subparsers.add_parser("status", help="Show SentinelX runtime status.")

    return parser


def start(args: argparse.Namespace) -> int:
    if args.threshold <= 0:
        print("Error: --threshold must be greater than 0.", file=sys.stderr)
        return 2

    existing_pid = read_pid()
    if existing_pid and process_exists(existing_pid):
        print(f"SentinelX is already running with PID {existing_pid}.", file=sys.stderr)
        return 1

    if not is_root():
        print(
            "Error: SentinelX start requires sudo/root privileges for packet capture.\n"
            "Try: sudo python main.py start --interface eth0",
            file=sys.stderr,
        )
        return 1

    write_runtime_state(args)

    alert_logger = None
    ui = RichUI(threshold=args.threshold)
    previous_sigint = None
    previous_sigterm = None

    try:
        detector = SuspiciousDetector()
        scorer = ThreatScorer(threshold=args.threshold)
        blocker = IPBlocker(enabled=not args.no_block)
        alert_logger = AlertLogger(args.log_file)
        sniffer = PacketSniffer(
            interface=args.interface,
            detector=detector,
            scorer=scorer,
            blocker=blocker,
            alert_logger=alert_logger,
            ui=ui,
        )

        def handle_shutdown(signum: int, _frame: Any) -> None:
            ui.alert("warning", f"Received signal {signum}; stopping SentinelX...")
            sniffer.stop()
            raise KeyboardInterrupt

        previous_sigint = signal.signal(signal.SIGINT, handle_shutdown)
        previous_sigterm = signal.signal(signal.SIGTERM, handle_shutdown)

        ui.print_banner(BANNER, VERSION)
        if args.no_block:
            ui.alert(
                "warning",
                "IPS blocking disabled by --no-block; running IDS-only.",
            )
        elif not blocker.available:
            ui.alert(
                "warning",
                "iptables blocking is unavailable on this platform; running IDS-only.",
            )
        sniffer.start()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        ui.alert("high", f"Fatal startup/runtime error: {exc}")
        return 1
    finally:
        if previous_sigint is not None:
            signal.signal(signal.SIGINT, previous_sigint)
        if previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)
        if alert_logger is not None:
            alert_logger.close()
        ui.stop()
        clear_runtime_state()


def stop(_: argparse.Namespace) -> int:
    pid = read_pid()
    if not pid:
        print("SentinelX is not running.")
        return 0
    if not process_exists(pid):
        clear_runtime_state()
        print("SentinelX is not running. Removed stale state.")
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
    except PermissionError:
        print(f"Permission denied stopping PID {pid}. Try sudo.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not stop SentinelX PID {pid}: {exc}", file=sys.stderr)
        return 1
    print(f"SentinelX stop signal sent to PID {pid}.")
    return 0


def status(_: argparse.Namespace) -> int:
    pid = read_pid()
    state: dict[str, Any] = {}
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    if pid and process_exists(pid):
        print(f"SentinelX status: RUNNING (PID {pid})")
        if state:
            print(f"Version: v{state.get('version', VERSION)}")
            print(f"Interface: {state.get('interface', 'unknown')}")
            print(f"Threshold: {state.get('threshold', 'unknown')}")
            print(f"Blocking: {'enabled' if state.get('blocking') else 'disabled'}")
            print(f"Started: {state.get('started_at', 'unknown')}")
        return 0

    if pid:
        clear_runtime_state()
        print("SentinelX status: STOPPED (stale state cleaned up)")
    else:
        print("SentinelX status: STOPPED")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "start":
        return start(args)
    if args.command == "stop":
        return stop(args)
    if args.command == "status":
        return status(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
