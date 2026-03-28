from __future__ import annotations

import random
from typing import List

from aegisnet_capture import AegisNetCapture

from .config import PipelineConfig
from .control_plane import ControlPlaneConfig, NodeControlClient
from .detection import FeatureRecord
from .storage import PipelineStorage


class TrafficPipeline:
    """Coordinates packet capture, feature routing, detection modules, and persistence."""

    def __init__(self, config: PipelineConfig):
        self.config = config.materialize()
        self.storage = PipelineStorage(self.config.database_path, server_url=self.config.server_url)
        self.control_client = None

        if self.config.control_enabled:
            control_cfg = ControlPlaneConfig(
                server_url=self.config.server_url,
                node_type="agent",
                enrollment_id=self.config.enrollment_id,
                domain_fqdn=self.config.domain_fqdn,
                dc_hint=self.config.dc_hint,
                capabilities={"flow_capture": True, "feature_ingest": True},
                metadata={"interfaces": [self.config.interface] if self.config.interface else []},
            )
            self.control_client = NodeControlClient(control_cfg)

        output_dir = str(self.config.capture_output_dir) if self.config.capture_output_dir else None
        self.capture = AegisNetCapture(
            interface=self.config.interface,
            output_dir=output_dir,
            feature_callback=self._handle_feature,
            write_to_csv=self.config.write_capture_csv,
        )

    def _handle_feature(self, feature_payload: dict) -> None:
        record = FeatureRecord(feature_payload)
        try:
            # Thin Agent: Just forward features to Cloud Storage
            self.storage.record_flow(record)
            
            # Simple logging
            self.storage.log("INFO", f"Captured flow {record.src_ip} -> {record.dst_ip} (sent to cloud)")
        except Exception as exc:  # pragma: no cover - defensive log path
            self.storage.log("ERROR", f"Failed to handle feature payload: {exc}")

    def run(self) -> None:
        import time
        iface = self.config.interface or "default-interface"
        self.storage.log("INFO", "Agent Process Started")

        if self.control_client:
            started = self.control_client.start()
            if started:
                self.storage.log("INFO", "Control-plane registration and websocket channel started")
            else:
                self.storage.log("WARNING", "Control-plane registration failed; continuing in ingest-only mode")

        while True:
            try:
                self.storage.log("INFO", f"Starting capture session on {iface}")
                self.capture.start_capture(duration=self.config.capture_duration)
                
                # If capture returns normally (e.g. duration expired), check if we should exit
                if self.config.capture_duration:
                     self.storage.log("INFO", "Specified duration completed. Exiting.")
                     break
            
            except KeyboardInterrupt:
                self.storage.log("INFO", "Agent stopped by user.")
                break
            except Exception as e:
                self.storage.log("CRITICAL", f"Capture crashed: {e}. Restarting in 5s...")
                time.sleep(5)
        
        if self.control_client:
            self.control_client.stop()
        self.storage.close()
