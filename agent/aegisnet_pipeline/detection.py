from __future__ import annotations
from dataclasses import dataclass
from typing import Dict

@dataclass
class FeatureRecord:
    """Lightweight view over the raw feature dictionary."""

    payload: Dict

    @property
    def src_ip(self) -> str:
        return str(self.payload.get("src_ip", "0.0.0.0"))

    @property
    def dst_ip(self) -> str:
        return str(self.payload.get("dst_ip", "0.0.0.0"))

    @property
    def src_port(self) -> int:
        value = self.payload.get("src_port")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def dst_port(self) -> int:
        value = self.payload.get("dst_port")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def protocol(self) -> int:
        value = self.payload.get("protocol")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def flow_duration(self) -> float:
        value = self.payload.get("flow_duration")
        try:
            return float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    @property
    def total_packets(self) -> int:
        value = self.payload.get("total_packets")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0
