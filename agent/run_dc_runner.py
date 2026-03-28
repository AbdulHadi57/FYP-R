#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import time

from aegisnet_pipeline.control_plane import ControlPlaneConfig, NodeControlClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AegisNet Domain Controller Runner (phase 1/2 control-plane)")
    parser.add_argument("--server", default="http://localhost:8000", help="AegisNet cloud backend URL")
    parser.add_argument("--domain", required=True, help="Domain FQDN (e.g., corp.local)")
    parser.add_argument("--forest", default=None, help="Forest FQDN")
    parser.add_argument("--site", default=None, help="AD site name")
    parser.add_argument("--fqdn", default=None, help="DC host FQDN")
    parser.add_argument("--dc-id", default=None, help="Existing DC id to re-register")
    parser.add_argument(
        "--response-url",
        default="http://127.0.0.1:5000/webhook",
        help="Local response webhook URL used for isolate_host/restore_host actions",
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main() -> None:
    args = build_parser().parse_args()
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
