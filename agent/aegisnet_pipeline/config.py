from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PipelineConfig:
    """Runtime configuration for the live detection pipeline."""

    interface: Optional[str] = None
    database_path: Path = Path("data/aegisnet_live.db")
    database_path: Path = Path("data/aegisnet_live.db")
    server_url: str = "http://localhost:8000"
    control_enabled: bool = True
    domain_fqdn: Optional[str] = None
    dc_hint: Optional[str] = None
    enrollment_id: Optional[str] = None
    enrollment_token: Optional[str] = None
    remote_db_url: Optional[str] = None
    db_connection_retries: int = 5
    capture_output_dir: Optional[Path] = Path("./captures")
    write_capture_csv: bool = False
    capture_duration: Optional[int] = None
    module_random_seed: int = 1337
    log_level: str = "INFO"
    max_queue_size: int = 5000

    def materialize(self) -> "PipelineConfig":
        """Ensure directories exist before the pipeline starts."""
        if self.database_path:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.capture_output_dir and self.write_capture_csv:
            self.capture_output_dir.mkdir(parents=True, exist_ok=True)
        return self

    def as_dict(self) -> dict:
        return {
            "interface": self.interface,
            "database_path": str(self.database_path) if self.database_path else None,
            "capture_output_dir": str(self.capture_output_dir) if self.capture_output_dir else None,
            "write_capture_csv": self.write_capture_csv,
            "capture_duration": self.capture_duration,
            "module_random_seed": self.module_random_seed,
            "log_level": self.log_level,
            "max_queue_size": self.max_queue_size,
            "control_enabled": self.control_enabled,
            "domain_fqdn": self.domain_fqdn,
            "dc_hint": self.dc_hint,
            "enrollment_id": self.enrollment_id,
        }
