from __future__ import annotations
import json
import logging
import requests
from datetime import UTC, datetime
from typing import Optional
from pathlib import Path
from .detection import FeatureRecord

class PipelineStorage:
    """Remote persistence via Cloud API (Thin Agent Mode)."""

    def __init__(self, db_path: Path, server_url: str = "http://localhost:8000"):
        self.logger = logging.getLogger("AegisNet.Storage")
        # Ensure it ends with /api/ingest
        base = server_url.rstrip("/")
        self.api_url = f"{base}/api/ingest"
        self.health_url = f"{base}/api/health"
        self.logger.info(f"Initialized Cloud Storage Client -> {self.api_url}")

    def _json_dump(self, payload: dict) -> str:
        def _default(obj):
            try:
                import numpy as np
                if isinstance(obj, np.generic): return obj.item()
            except: pass
            if isinstance(obj, bytes): return obj.decode("latin-1", errors="ignore")
            return str(obj)
        return json.dumps(payload, default=_default)

    def record_flow(self, record: FeatureRecord) -> int:
        captured_at = datetime.now(UTC).isoformat()
        
        # Prepare Thin Client Payload
        payload = {
            "captured_at": captured_at,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "src_port": record.src_port,
            "dst_port": record.dst_port,
            "protocol": record.protocol,
            "total_packets": record.total_packets,
            "flow_duration": record.flow_duration,
            "payload": record.payload # Raw features sent to cloud for analysis
        }

        try:
            # Send to Cloud
            resp = requests.post(self.api_url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                # Return flow ID so orchestrator can log it
                return data.get("flow_id", 0)
            else:
                self.logger.error(f"Cloud API Error {resp.status_code}: {resp.text}")
                return -1
        except Exception as e:
            self.logger.error(f"Failed to send flow to cloud ({self.api_url}): {e}")
            return -1

    def check_backend_health(self) -> bool:
        try:
            resp = requests.get(self.health_url, timeout=5)
            return resp.status_code == 200
        except Exception as exc:
            self.logger.warning(f"Backend health check failed ({self.health_url}): {exc}")
            return False

    def log(self, level: str, message: str) -> None:
        lvl_map = {"INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR, "DEBUG": logging.DEBUG, "CRITICAL": logging.CRITICAL}
        self.logger.log(lvl_map.get(level.upper(), logging.INFO), message)

    def close(self) -> None:
        pass
