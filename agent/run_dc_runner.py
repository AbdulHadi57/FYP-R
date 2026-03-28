#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import logging
import os
import re
import time

from aegisnet_pipeline.control_plane import ControlPlaneConfig, NodeControlClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AegisNet Domain Controller Runner (single-process mode)")
    parser.add_argument("--server", default=None, help="AegisNet cloud backend URL (e.g., http://10.0.2.5:8000)")
    parser.add_argument("--domain", default=None, help="Domain FQDN (e.g., corp.local)")
    parser.add_argument("--forest", default=None, help="Forest FQDN")
    parser.add_argument("--site", default=None, help="AD site name")
    parser.add_argument("--fqdn", default=None, help="DC host FQDN (optional; defaults to domain)")
    parser.add_argument("--dc-id", default=None, help="Existing DC id to re-register")
    parser.add_argument("--admin-user", default=None, help="AD admin user for direct isolate/restore")
    parser.add_argument("--admin-pass", default=None, help="AD admin password for direct isolate/restore")
    parser.add_argument("--dc-ip", default=None, help="DC management IP to keep allow-listed during isolation")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable interactive prompts and require all needed values via flags/env",
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _normalize_server_url(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return v

    # Accept plain IP/hostname and normalize to http://<host>:8000.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", v):
        if ":" in v:
            v = f"http://{v}"
        else:
            v = f"http://{v}:8000"
    return v


def _prompt(label: str, default: str | None = None, required: bool = False, secret: bool = False) -> str | None:
    while True:
        prompt = label
        if default:
            prompt += f" [{default}]"
        prompt += ": "

        value = getpass.getpass(prompt) if secret else input(prompt).strip()
        if not value and default is not None:
            value = default

        if value:
            return value
        if not required:
            return None

        print("This value is required.")


def _apply_interactive_defaults(args: argparse.Namespace) -> argparse.Namespace:
    if args.non_interactive:
        return args

    print("AegisNet DC Runner setup (interactive)")
    print("Press Enter to accept defaults.")

    if not args.server:
        args.server = _prompt("Cloud server IP or URL", required=True)
    args.server = _normalize_server_url(args.server)

    args.domain = args.domain or _prompt("Domain FQDN", required=True)
    args.fqdn = args.fqdn or _prompt("DC FQDN (optional)", default=args.domain, required=False)

    if args.forest is None:
        args.forest = _prompt("Forest FQDN", required=False)
    if args.site is None:
        args.site = _prompt("Site name", required=False)
    if args.dc_id is None:
        args.dc_id = _prompt("Existing DC id (optional)", required=False)

    # One-process direct containment mode.
    if args.admin_user is None:
        args.admin_user = _prompt("AD admin user", default=os.getenv("AEGIS_ADMIN_USER"), required=False)
    if args.admin_pass is None:
        env_pass = os.getenv("AEGIS_ADMIN_PASS")
        args.admin_pass = env_pass or _prompt("AD admin password", required=False, secret=True)
    if args.dc_ip is None:
        args.dc_ip = _prompt("DC management IP", default=os.getenv("AEGIS_DC_IP"), required=False)

    return args


def main() -> None:
    args = build_parser().parse_args()
    args = _apply_interactive_defaults(args)

    args.server = _normalize_server_url(args.server)

    if not args.server:
        raise SystemExit("Missing required server URL/IP. Provide --server or run interactive mode.")
    if not args.domain:
        raise SystemExit("Missing required domain. Provide --domain or run interactive mode.")
    if not args.fqdn:
        args.fqdn = args.domain

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cfg = ControlPlaneConfig(
        server_url=args.server,
        node_type="dc",
        enrollment_id=args.dc_id,
        domain_fqdn=args.domain,
        capabilities={"ad_response": True, "script_exec": True},
        metadata={
            "fqdn": args.fqdn,
            "forest_fqdn": args.forest,
            "site_name": args.site,
        },
        ad_admin_user=args.admin_user,
        ad_admin_pass=args.admin_pass,
        dc_ip=args.dc_ip,
    )

    client = NodeControlClient(cfg)
    if not client.start():
        raise SystemExit("Failed to start DC runner control-plane registration")

    logging.getLogger("AegisNet.DCRunner").info("DC runner connected as %s", client.node_id)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()


if __name__ == "__main__":
    main()
