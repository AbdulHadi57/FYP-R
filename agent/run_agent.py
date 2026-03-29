#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import platform
import re
from pathlib import Path

from aegisnet_pipeline import PipelineConfig, TrafficPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the AegisNet live detection pipeline (Agent Mode)")
    parser.add_argument("--interface", "-i", help="Network interface to sniff (default: scapy default interface)")
    parser.add_argument("--db", default="data/aegisnet_live.db", help="Path to the SQLite database used by the dashboard")
    parser.add_argument("--duration", "-d", type=int, help="Optional capture duration in seconds")
    parser.add_argument(
        "--write-csv",
        action="store_true",
        help="Persist CSV snapshots in addition to feeding the dashboard (default: disabled)",
    )
    parser.add_argument(
        "--capture-output",
        default="captures",
        help="Directory to store CSV snapshots when --write-csv is set",
    )
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for placeholder models")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity")
    parser.add_argument("--server", default="http://localhost:8000", help="URL of the AegisNet Cloud Backend API")
    parser.add_argument("--disable-control", action="store_true", help="Disable control-plane registration and websocket channel")
    parser.add_argument("--domain", default=None, help="Domain FQDN for control-plane registration (e.g., corp.local)")
    parser.add_argument("--dc-hint", default=None, help="Preferred domain controller id/hostname for binding")
    parser.add_argument("--enrollment-id", default=None, help="Existing node id to re-register (optional)")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable interactive prompts and rely only on flags/defaults",
    )
    return parser


def _normalize_server_url(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return v

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", v):
        if ":" in v:
            v = f"http://{v}"
        else:
            v = f"http://{v}:8000"
    return v


def _default_interface() -> str:
    return "eth0" if platform.system().lower() != "windows" else "Ethernet"


def _prompt(label: str, default: str | None = None, required: bool = False) -> str | None:
    while True:
        prompt = label
        if default not in (None, ""):
            prompt += f" [{default}]"
        prompt += ": "

        value = input(prompt).strip()
        if not value and default is not None:
            value = default

        if value:
            return value
        if not required:
            return None

        print("This value is required.")


def _prompt_bool(label: str, default: bool = False) -> bool:
    default_hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{label} [{default_hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "true", "1"}:
            return True
        if raw in {"n", "no", "false", "0"}:
            return False
        print("Please answer y or n.")


def _apply_interactive_defaults(args: argparse.Namespace) -> argparse.Namespace:
    if args.non_interactive:
        return args

    print("AegisNet Agent setup (interactive)")
    print("Press Enter to accept defaults.")

    args.server = _normalize_server_url(
        args.server or _prompt("Cloud server IP or URL", default="http://localhost:8000", required=True)
    )
    args.interface = args.interface or _prompt("Network interface", default=_default_interface(), required=True)
    args.domain = args.domain or _prompt("Domain FQDN", required=True)

    if args.dc_hint is None:
        args.dc_hint = _prompt("Preferred DC id/hostname (optional)", required=False)
    if args.enrollment_id is None:
        args.enrollment_id = _prompt("Existing agent id (optional)", required=False)

    if args.db is None:
        args.db = _prompt("Local DB path", default="data/aegisnet_live.db", required=True)
    if args.log_level is None:
        args.log_level = _prompt("Log level", default="INFO", required=True)

    if args.duration is None:
        raw_duration = _prompt("Capture duration in seconds (optional)", required=False)
        args.duration = int(raw_duration) if raw_duration else None

    if not args.write_csv:
        args.write_csv = _prompt_bool("Write CSV snapshots", default=False)
    if args.write_csv and not args.capture_output:
        args.capture_output = _prompt("Capture output directory", default="captures", required=True)

    if args.seed is None:
        raw_seed = _prompt("Random seed", default="1337", required=True)
        args.seed = int(raw_seed)

    if not args.disable_control:
        args.disable_control = _prompt_bool("Disable control-plane channel", default=False)

    return args


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args = _apply_interactive_defaults(args)

    args.server = _normalize_server_url(args.server)
    if not args.interface:
        args.interface = _default_interface()
    
    # Configure structured logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    if platform.system().lower() != "windows" and hasattr(os, "geteuid") and os.geteuid() != 0:
        logging.getLogger("AegisNet.AgentRunner").warning(
            "Packet capture typically requires root privileges on Linux. "
            "If dashboard stays static, rerun with sudo and verify interface selection."
        )

    config = PipelineConfig(
        interface=args.interface,
        database_path=Path(args.db),
        server_url=args.server,
        capture_output_dir=Path(args.capture_output) if args.capture_output else None,
        write_capture_csv=bool(args.write_csv),
        capture_duration=args.duration,
        module_random_seed=args.seed,
        log_level=args.log_level,
        control_enabled=not args.disable_control,
        domain_fqdn=args.domain,
        dc_hint=args.dc_hint,
        enrollment_id=args.enrollment_id,
    )
    
    pipeline = TrafficPipeline(config)
    pipeline.run()


if __name__ == "__main__":
    main()
