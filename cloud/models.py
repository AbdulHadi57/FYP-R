from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class Flow(BaseModel):
    id: int
    captured_at: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    total_packets: int
    flow_duration: float
    verdict: str
    ja4_pred: Optional[str] = "none"
    doh_pred: Optional[str] = "none"
    apt_pred: Optional[str] = "none"
    confidence: float
    severity: float
    summary: str
    features_json: Optional[str] = "{}"
    sni: Optional[str] = None

class FlowDetail(BaseModel):
    id: int
    features: Dict[str, Any]

class Stats(BaseModel):
    total_flows: int
    malicious_flows: int
    avg_severity: float
    top_source: str
    top_attackers: List[dict]
    last_flow_timestamp: Optional[str] = None

class TimelinePoint(BaseModel):
    bucket: str
    flow_count: int
    malicious_count: int

class ModuleStats(BaseModel):
    ja4_diversity: int
    ja4s_diversity: int
    top_ja4: List[dict]
    top_ja4s: List[dict]
    top_ja4h: List[dict]
    top_ja4x: List[dict]
    top_ja4ssh: List[dict]
    top_ja4t: List[dict]
    top_ja4ts: List[dict]
    top_ja4l: List[dict]
    top_ja4d: List[dict]
    doh_stats: List[Dict[str, Any]]
    doh_detection_stats: dict # Stage 1: DoH vs Non-DoH
    doh_classification_stats: dict # Stage 2: Malicious vs Benign DoH
    ja4_malicious_count: int = 0
    ja4_benign_count: int = 0
    ja4_malicious_flows: List[Dict[str, Any]] = []
    doh_malicious_flows: List[Dict[str, Any]] = []
    apt_stats: List[Dict[str, Any]]
    recent_features: Dict[str, List[Dict[str, Any]]] = {}
    module_activity: Dict[str, int] = {} # {ja4: N, doh: N, apt: N}
    threat_status_distribution: Dict[str, int] = {} # {open: N, resolved: N}


class ActionableEvent(BaseModel):
    id: str
    flow_id: Optional[int] = None
    timestamp: str  # ISO format
    severity: str   # critical, high, medium, low, info
    category: str   # threat, system, compliance, network
    module_source: str # ja4, doh, apt, general, system
    confidence: Optional[float] = None # 0.0 - 1.0, None for system logs
    title: str
    message: str
    source_ip: Optional[str] = None
    affected_asset: Optional[str] = None
    action_required: bool = False
    recommended_action: Optional[str] = None
    status: str = "open" # open, investigating, resolved
    resolution_note: Optional[str] = None

class ResolutionRequest(BaseModel):
    note: str

class ForensicsStats(BaseModel):
    flag_counts: List[Dict[str, Any]]
    payload_stats: Dict[str, List[int]]
    top_ports: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]

class IngestModuleResult(BaseModel):
    module: str
    label: str
    confidence: float
    score: float
    rationale: str

class IngestRequest(BaseModel):
    captured_at: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    total_packets: int
    flow_duration: float
    ja4: str
    ja4s: str
    ja4h: str
    ja4_pred: str
    doh_pred: str
    apt_pred: str
    verdict: str
    confidence: float
    severity: float
    summary: str
    features_json: str
    module_results: List[IngestModuleResult]

class FeatureIngestRequest(BaseModel):
    captured_at: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    total_packets: int
    flow_duration: float
    payload: Dict[str, Any]  # The raw feature dictionary from the agent


class AgentRegistrationRequest(BaseModel):
    agent_id: Optional[str] = None
    hostname: str
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    domain_fqdn: Optional[str] = None
    dc_hint: Optional[str] = None
    interfaces: List[str] = []
    ip_addresses: List[str] = []
    capabilities: Dict[str, Any] = {}


class DcRegistrationRequest(BaseModel):
    dc_id: Optional[str] = None
    hostname: str
    fqdn: Optional[str] = None
    domain_fqdn: Optional[str] = None
    forest_fqdn: Optional[str] = None
    site_name: Optional[str] = None
    os_version: Optional[str] = None
    runner_version: Optional[str] = None
    capabilities: Dict[str, Any] = {}


class RegistrationResponse(BaseModel):
    node_id: str
    node_type: str
    auth_token: str
    heartbeat_interval_seconds: int
    websocket_path: str


class HeartbeatRequest(BaseModel):
    auth_token: str
    status: str = "online"
    payload: Dict[str, Any] = {}


class NodeSummary(BaseModel):
    id: str
    hostname: str
    status: str
    last_seen: Optional[str] = None
    domain_fqdn: Optional[str] = None
    dc_id: Optional[str] = None
    primary_ip: Optional[str] = None


class CreateActionRequest(BaseModel):
    target_type: str  # agent | dc
    target_id: str
    action_type: str
    payload: Dict[str, Any] = {}
    requested_by: str = "system"
    reason: str = "automated-response"
    require_approval: Optional[bool] = None


class ActionStatusUpdateRequest(BaseModel):
    auth_token: str
    status: str  # accepted | running | succeeded | failed
    result: Dict[str, Any] = {}


class ApproveActionRequest(BaseModel):
    approved_by: str
    approved: bool = True
    note: Optional[str] = None


class RollbackActionRequest(BaseModel):
    requested_by: str = "system"
    reason: str = "rollback"


class ActionJobResponse(BaseModel):
    id: str
    target_type: str
    target_id: str
    action_type: str
    payload: Dict[str, Any] = {}
    status: str
    approval_required: bool = False
    approval_status: str = "not_required"
    rollback_of_action_id: Optional[str] = None
    requested_by: Optional[str] = None
    reason: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ResponseTemplateUpsertRequest(BaseModel):
    name: str
    description: Optional[str] = None
    target_action_type: str  # e.g., isolate_host, restore_host
    default_payload: Dict[str, Any] = {}
    require_approval: bool = True
    enabled: bool = True


class ResponseTemplateSummary(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    target_action_type: str
    default_payload: Dict[str, Any] = {}
    require_approval: bool = True
    enabled: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class TemplateDispatchRequest(BaseModel):
    template_name: str
    agent_id: str
    target_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    payload_overrides: Dict[str, Any] = {}
    requested_by: str = "system"
    reason: str = "templated-response"
    require_approval: Optional[bool] = None


class TemplateDispatchResponse(BaseModel):
    template_name: str
    agent_id: str
    resolved_dc_id: str
    action: ActionJobResponse
