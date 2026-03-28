#!/usr/bin/env python3
from __future__ import annotations

import logging
import argparse
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
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    
    # Set default values for debugging if not provided
    if not args.interface:
        args.interface = "eth0"  # Use scapy default
    
    # Configure structured logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
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
