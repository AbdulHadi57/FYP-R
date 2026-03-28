#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import logging
import os
import time

from aegisnet_pipeline.control_plane import ControlPlaneConfig, NodeControlClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AegisNet Domain Controller Runner (single-process mode)")
    parser.add_argument("--server", default="http://localhost:8000", help="AegisNet cloud backend URL")
    parser.add_argument("--domain", default=None, help="Domain FQDN (e.g., corp.local)")
    parser.add_argument("--forest", default=None, help="Forest FQDN")
    parser.add_argument("--site", default=None, help="AD site name")
    parser.add_argument("--fqdn", default=None, help="DC host FQDN")
    parser.add_argument("--dc-id", default=None, help="Existing DC id to re-register")
    parser.add_argument(
        "--response-url",
        default=None,
        help="Optional local webhook URL for isolate_host/restore_host compatibility mode",
    )
    parser.add_argument("--webhook-secret", default=None, help="Optional X-Webhook-Secret when using --response-url")
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

    args.server = args.server or _prompt("Cloud server URL", default="http://localhost:8000", required=True)
    args.domain = args.domain or _prompt("Domain FQDN", required=True)
    args.fqdn = args.fqdn or _prompt("DC FQDN", required=True)

    if args.forest is None:
        args.forest = _prompt("Forest FQDN", required=False)
    if args.site is None:
        args.site = _prompt("Site name", required=False)
    if args.dc_id is None:
        args.dc_id = _prompt("Existing DC id (optional)", required=False)

    # One-process default: direct containment in runner. Webhook mode remains optional.
    if args.response_url is None:
        mode = _prompt("Use external webhook for isolate/restore? (y/N)", default="N", required=False)
        if (mode or "").strip().lower() in {"y", "yes"}:
            args.response_url = _prompt("Webhook URL", default="http://127.0.0.1:5000/webhook", required=True)
            if args.webhook_secret is None:
                args.webhook_secret = _prompt("Webhook secret (optional)", required=False, secret=True)
        else:
            print("Using direct isolate/restore execution inside this runner process.")

    if not args.response_url:
        # Direct mode credentials (optional prompt; can also come from env).
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

    if not args.domain:
        raise SystemExit("Missing required domain. Provide --domain or run interactive mode.")
    if not args.fqdn:
        raise SystemExit("Missing required DC FQDN. Provide --fqdn or run interactive mode.")

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
        response_webhook_url=args.response_url,
        webhook_secret=args.webhook_secret,
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
