from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime
from typing import Dict, Optional, Tuple

from fastapi import APIRouter, HTTPException, Header, WebSocket, WebSocketDisconnect

from database import get_db_connection
from models import (
    ActionJobResponse,
    ActionStatusUpdateRequest,
    AgentRegistrationRequest,
    ApproveActionRequest,
    CreateActionRequest,
    DcRegistrationRequest,
    HeartbeatRequest,
    NodeSummary,
    RegistrationResponse,
    ResponseTemplateSummary,
    ResponseTemplateUpsertRequest,
    TemplateDispatchRequest,
    TemplateDispatchResponse,
    RollbackActionRequest,
)


HEARTBEAT_INTERVAL_SECONDS = 15
CONTROL_API_KEY = os.getenv("AEGIS_CONTROL_API_KEY", "").strip()

# Action policy keeps command surface explicit and auditable.
ACTION_POLICY = {
    "agent": {
        "ping": {"approval": False},
        "noop": {"approval": False},
        "log_message": {"approval": False},
        "block_ip": {"approval": True, "rollback_action": "unblock_ip", "rollback_payload_builder": "same"},
        "unblock_ip": {"approval": False},
        "quarantine_host": {"approval": True, "rollback_action": "unquarantine_host", "rollback_payload_builder": "same"},
        "unquarantine_host": {"approval": False},
    },
    "dc": {
        "ping": {"approval": False},
        "noop": {"approval": False},
        "log_message": {"approval": False},
        "isolate_host": {"approval": True, "rollback_action": "restore_host", "rollback_payload_builder": "same"},
        "restore_host": {"approval": False},
        "disable_ad_user": {"approval": True, "rollback_action": "enable_ad_user", "rollback_payload_builder": "same"},
        "enable_ad_user": {"approval": False},
        "disable_ad_computer": {"approval": True, "rollback_action": "enable_ad_computer", "rollback_payload_builder": "same"},
        "enable_ad_computer": {"approval": False},
    },
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _require_operator_key(x_control_key: Optional[str]) -> None:
    """Protect operator APIs when AEGIS_CONTROL_API_KEY is configured."""
    if not CONTROL_API_KEY:
        return
    if x_control_key != CONTROL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid control API key")


class ConnectionRegistry:
    """Tracks currently connected control channels (agent or dc)."""

    def __init__(self):
        self.connections: Dict[Tuple[str, str], WebSocket] = {}

    async def connect(self, node_type: str, node_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self.connections[(node_type, node_id)] = ws

    def disconnect(self, node_type: str, node_id: str) -> None:
        self.connections.pop((node_type, node_id), None)

    def get(self, node_type: str, node_id: str) -> Optional[WebSocket]:
        return self.connections.get((node_type, node_id))

    async def send_action(self, node_type: str, node_id: str, action: dict) -> bool:
        ws = self.get(node_type, node_id)
        if not ws:
            return False
        await ws.send_json({"type": "action", "payload": action})
        return True


registry = ConnectionRegistry()
router = APIRouter(prefix="/api/control", tags=["control-plane"])


def _node_table(node_type: str) -> str:
    if node_type == "agent":
        return "agents"
    if node_type == "dc":
        return "domain_controllers"
    raise HTTPException(status_code=400, detail="node_type must be 'agent' or 'dc'")


def _validate_node_token(conn, node_type: str, node_id: str, token: str) -> bool:
    table = _node_table(node_type)
    row = conn.execute(f"SELECT auth_token FROM {table} WHERE id = ?", (node_id,)).fetchone()
    return bool(row and row["auth_token"] == token)


def _audit(conn, action_id: str, event_type: str, actor: str, details: dict):
    conn.execute(
        """
        INSERT INTO action_audit_logs (action_id, event_type, actor, details_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (action_id, event_type, actor, json.dumps(details), _now_iso()),
    )


def _policy_for(target_type: str, action_type: str) -> dict:
    policy = ACTION_POLICY.get(target_type, {})
    action_policy = policy.get(action_type)
    if not action_policy:
        raise HTTPException(
            status_code=400,
            detail=f"Action '{action_type}' is not allowed for target_type '{target_type}'",
        )
    return action_policy


def _build_rollback(action_policy: dict, payload: dict) -> tuple[Optional[str], Optional[dict]]:
    rollback_action = action_policy.get("rollback_action")
    if not rollback_action:
        return None, None

    if action_policy.get("rollback_payload_builder") == "same":
        return rollback_action, payload
    return rollback_action, {}


def _action_row_to_response(row) -> ActionJobResponse:
    return ActionJobResponse(
        id=row["id"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        action_type=row["action_type"],
        status=row["status"],
        approval_required=bool(row["approval_required"]),
        approval_status=row["approval_status"] or "not_required",
        rollback_of_action_id=row["rollback_of_action_id"],
        requested_by=row["requested_by"],
        reason=row["reason"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _template_row_to_response(row) -> ResponseTemplateSummary:
    try:
        payload = json.loads(row["default_payload_json"] or "{}")
    except Exception:
        payload = {}

    return ResponseTemplateSummary(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        target_action_type=row["target_action_type"],
        default_payload=payload,
        require_approval=bool(row["require_approval"]),
        enabled=bool(row["enabled"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def _dispatch_queued_action(action_id: str) -> None:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        if not row:
            return
        if row["status"] != "queued":
            return

        sent = await registry.send_action(row["target_type"], row["target_id"], dict(row))
        if sent:
            now = _now_iso()
            conn.execute(
                "UPDATE action_jobs SET status = 'dispatched', dispatched_at = ?, updated_at = ? WHERE id = ?",
                (now, now, action_id),
            )
            _audit(conn, action_id, "dispatched", "control-plane", {"target": row["target_id"]})
            conn.commit()
    finally:
        conn.close()


async def _dispatch_pending(node_type: str, node_id: str) -> None:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT id FROM action_jobs
            WHERE target_type = ? AND target_id = ? AND status = 'queued'
            ORDER BY created_at ASC
            LIMIT 25
            """,
            (node_type, node_id),
        ).fetchall()
    finally:
        conn.close()

    for row in rows:
        await _dispatch_queued_action(row["id"])


def _mark_node_status(node_type: str, node_id: str, status: str) -> None:
    table = _node_table(node_type)
    conn = get_db_connection()
    try:
        now = _now_iso()
        conn.execute(
            f"UPDATE {table} SET status = ?, updated_at = ?, last_seen = COALESCE(last_seen, ?) WHERE id = ?",
            (status, now, now, node_id),
        )
        conn.commit()
    finally:
        conn.close()


def _resolve_dc_for_agent(conn, agent_id: str) -> str:
    # 1) Prefer active explicit binding.
    bound = conn.execute(
        """
        SELECT b.dc_id
        FROM agent_dc_bindings b
        JOIN domain_controllers d ON d.id = b.dc_id
        WHERE b.agent_id = ? AND b.is_active = 1
        ORDER BY b.id DESC
        LIMIT 1
        """,
        (agent_id,),
    ).fetchone()
    if bound:
        return bound["dc_id"]

    # 2) Fallback by agent hint if present.
    agent_row = conn.execute(
        "SELECT id, dc_hint, domain_fqdn FROM agents WHERE id = ?",
        (agent_id,),
    ).fetchone()
    if not agent_row:
        raise HTTPException(status_code=404, detail="Agent not found")

    dc_hint = (agent_row["dc_hint"] or "").strip()
    if dc_hint:
        hinted = conn.execute(
            "SELECT id FROM domain_controllers WHERE id = ? OR hostname = ? OR fqdn = ? LIMIT 1",
            (dc_hint, dc_hint, dc_hint),
        ).fetchone()
        if hinted:
            return hinted["id"]

    # 3) Fallback by domain affinity.
    domain_fqdn = (agent_row["domain_fqdn"] or "").strip()
    if domain_fqdn:
        dc = conn.execute(
            """
            SELECT id
            FROM domain_controllers
            WHERE domain_fqdn = ?
            ORDER BY CASE WHEN status = 'online' THEN 0 ELSE 1 END, updated_at DESC
            LIMIT 1
            """,
            (domain_fqdn,),
        ).fetchone()
        if dc:
            return dc["id"]

    # 4) Last resort, choose freshest online DC.
    dc = conn.execute(
        """
        SELECT id
        FROM domain_controllers
        ORDER BY CASE WHEN status = 'online' THEN 0 ELSE 1 END, updated_at DESC
        LIMIT 1
        """
    ).fetchone()
    if dc:
        return dc["id"]

    raise HTTPException(status_code=409, detail="No domain controller available for this agent")


@router.post("/register/agent", response_model=RegistrationResponse)
def register_agent(request: AgentRegistrationRequest):
    conn = get_db_connection()
    try:
        node_id = request.agent_id or _new_id("agt")
        token_row = conn.execute("SELECT auth_token FROM agents WHERE id = ?", (node_id,)).fetchone()
        auth_token = token_row["auth_token"] if token_row else _new_token()
        now = _now_iso()

        conn.execute(
            """
            INSERT INTO agents (
                id, hostname, os_type, os_version, agent_version, domain_fqdn, dc_hint,
                interfaces_json, capabilities_json, auth_token, status, last_seen, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname,
                os_type=excluded.os_type,
                os_version=excluded.os_version,
                agent_version=excluded.agent_version,
                domain_fqdn=excluded.domain_fqdn,
                dc_hint=excluded.dc_hint,
                interfaces_json=excluded.interfaces_json,
                capabilities_json=excluded.capabilities_json,
                status='online',
                last_seen=excluded.last_seen,
                updated_at=excluded.updated_at
            """,
            (
                node_id,
                request.hostname,
                request.os_type,
                request.os_version,
                request.agent_version,
                request.domain_fqdn,
                request.dc_hint,
                json.dumps(request.interfaces),
                json.dumps(request.capabilities),
                auth_token,
                now,
                now,
            ),
        )

        if request.dc_hint:
            dc_row = conn.execute(
                "SELECT id FROM domain_controllers WHERE id = ? OR hostname = ? OR fqdn = ?",
                (request.dc_hint, request.dc_hint, request.dc_hint),
            ).fetchone()
            if dc_row:
                conn.execute("UPDATE agent_dc_bindings SET is_active = 0 WHERE agent_id = ?", (node_id,))
                conn.execute(
                    """
                    INSERT INTO agent_dc_bindings (agent_id, dc_id, binding_source, is_active)
                    VALUES (?, ?, 'agent_hint', 1)
                    """,
                    (node_id, dc_row["id"]),
                )

        conn.commit()
        return RegistrationResponse(
            node_id=node_id,
            node_type="agent",
            auth_token=auth_token,
            heartbeat_interval_seconds=HEARTBEAT_INTERVAL_SECONDS,
            websocket_path=f"/api/control/ws/control/agent/{node_id}",
        )
    finally:
        conn.close()


@router.post("/register/dc", response_model=RegistrationResponse)
def register_dc(request: DcRegistrationRequest):
    conn = get_db_connection()
    try:
        node_id = request.dc_id or _new_id("dc")
        token_row = conn.execute("SELECT auth_token FROM domain_controllers WHERE id = ?", (node_id,)).fetchone()
        auth_token = token_row["auth_token"] if token_row else _new_token()
        now = _now_iso()

        conn.execute(
            """
            INSERT INTO domain_controllers (
                id, hostname, fqdn, domain_fqdn, forest_fqdn, site_name,
                os_version, runner_version, capabilities_json, auth_token,
                status, last_seen, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname,
                fqdn=excluded.fqdn,
                domain_fqdn=excluded.domain_fqdn,
                forest_fqdn=excluded.forest_fqdn,
                site_name=excluded.site_name,
                os_version=excluded.os_version,
                runner_version=excluded.runner_version,
                capabilities_json=excluded.capabilities_json,
                status='online',
                last_seen=excluded.last_seen,
                updated_at=excluded.updated_at
            """,
            (
                node_id,
                request.hostname,
                request.fqdn,
                request.domain_fqdn,
                request.forest_fqdn,
                request.site_name,
                request.os_version,
                request.runner_version,
                json.dumps(request.capabilities),
                auth_token,
                now,
                now,
            ),
        )
        conn.commit()
        return RegistrationResponse(
            node_id=node_id,
            node_type="dc",
            auth_token=auth_token,
            heartbeat_interval_seconds=HEARTBEAT_INTERVAL_SECONDS,
            websocket_path=f"/api/control/ws/control/dc/{node_id}",
        )
    finally:
        conn.close()


@router.post("/heartbeat/agent/{agent_id}")
def heartbeat_agent(agent_id: str, request: HeartbeatRequest):
    conn = get_db_connection()
    try:
        if not _validate_node_token(conn, "agent", agent_id, request.auth_token):
            raise HTTPException(status_code=401, detail="Invalid node token")

        now = _now_iso()
        conn.execute(
            "UPDATE agents SET status = ?, last_seen = ?, updated_at = ? WHERE id = ?",
            (request.status, now, now, agent_id),
        )
        conn.execute(
            "INSERT INTO heartbeats (node_id, node_type, status, payload_json, captured_at) VALUES (?, 'agent', ?, ?, ?)",
            (agent_id, request.status, json.dumps(request.payload), now),
        )
        conn.commit()
        return {"status": "ok", "node_id": agent_id, "captured_at": now}
    finally:
        conn.close()


@router.post("/heartbeat/dc/{dc_id}")
def heartbeat_dc(dc_id: str, request: HeartbeatRequest):
    conn = get_db_connection()
    try:
        if not _validate_node_token(conn, "dc", dc_id, request.auth_token):
            raise HTTPException(status_code=401, detail="Invalid node token")

        now = _now_iso()
        conn.execute(
            "UPDATE domain_controllers SET status = ?, last_seen = ?, updated_at = ? WHERE id = ?",
            (request.status, now, now, dc_id),
        )
        conn.execute(
            "INSERT INTO heartbeats (node_id, node_type, status, payload_json, captured_at) VALUES (?, 'dc', ?, ?, ?)",
            (dc_id, request.status, json.dumps(request.payload), now),
        )
        conn.commit()
        return {"status": "ok", "node_id": dc_id, "captured_at": now}
    finally:
        conn.close()


@router.get("/agents", response_model=list[NodeSummary])
def list_agents(
    limit: int = 200,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, hostname, status, last_seen, domain_fqdn FROM agents ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [NodeSummary(**dict(row)) for row in rows]
    finally:
        conn.close()


@router.get("/dcs", response_model=list[NodeSummary])
def list_dcs(
    limit: int = 200,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, hostname, status, last_seen, domain_fqdn FROM domain_controllers ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [NodeSummary(**dict(row)) for row in rows]
    finally:
        conn.close()


@router.get("/responses/templates", response_model=list[ResponseTemplateSummary])
def list_response_templates(
    enabled_only: bool = True,
    limit: int = 200,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        if enabled_only:
            rows = conn.execute(
                "SELECT * FROM response_templates WHERE enabled = 1 ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM response_templates ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_template_row_to_response(row) for row in rows]
    finally:
        conn.close()


@router.post("/responses/templates", response_model=ResponseTemplateSummary)
def upsert_response_template(
    request: ResponseTemplateUpsertRequest,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        now = _now_iso()
        existing = conn.execute("SELECT id FROM response_templates WHERE name = ?", (request.name,)).fetchone()
        template_id = existing["id"] if existing else _new_id("tpl")

        conn.execute(
            """
            INSERT INTO response_templates (
                id, name, description, target_action_type,
                default_payload_json, require_approval, enabled,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                target_action_type = excluded.target_action_type,
                default_payload_json = excluded.default_payload_json,
                require_approval = excluded.require_approval,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            """,
            (
                template_id,
                request.name,
                request.description,
                request.target_action_type,
                json.dumps(request.default_payload),
                1 if request.require_approval else 0,
                1 if request.enabled else 0,
                now,
                now,
            ),
        )
        conn.commit()

        row = conn.execute("SELECT * FROM response_templates WHERE name = ?", (request.name,)).fetchone()
        return _template_row_to_response(row)
    finally:
        conn.close()


@router.post("/responses/dispatch", response_model=TemplateDispatchResponse)
async def dispatch_template_response(
    request: TemplateDispatchRequest,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        template_row = conn.execute(
            "SELECT * FROM response_templates WHERE name = ? AND enabled = 1",
            (request.template_name,),
        ).fetchone()
        if not template_row:
            raise HTTPException(status_code=404, detail="Response template not found or disabled")

        resolved_dc_id = _resolve_dc_for_agent(conn, request.agent_id)

        try:
            default_payload = json.loads(template_row["default_payload_json"] or "{}")
        except Exception:
            default_payload = {}

        payload = dict(default_payload)
        payload.update(request.payload_overrides)
        payload["target_ip"] = request.target_ip
        if request.target_port is not None:
            payload["target_port"] = request.target_port
        if request.protocol:
            payload["protocol"] = request.protocol
        payload["origin_agent_id"] = request.agent_id

        force_approval = request.require_approval
        if force_approval is None:
            force_approval = bool(template_row["require_approval"])
    finally:
        conn.close()

    action = await create_action(
        CreateActionRequest(
            target_type="dc",
            target_id=resolved_dc_id,
            action_type=template_row["target_action_type"],
            payload=payload,
            requested_by=request.requested_by,
            reason=request.reason,
            require_approval=force_approval,
        ),
        x_control_key=x_control_key,
    )

    conn = get_db_connection()
    try:
        _audit(
            conn,
            action.id,
            "templated_dispatch",
            request.requested_by,
            {
                "template_name": request.template_name,
                "origin_agent_id": request.agent_id,
                "resolved_dc_id": resolved_dc_id,
                "target_ip": request.target_ip,
                "target_port": request.target_port,
                "protocol": request.protocol,
            },
        )
        conn.commit()
    finally:
        conn.close()

    return TemplateDispatchResponse(
        template_name=request.template_name,
        agent_id=request.agent_id,
        resolved_dc_id=resolved_dc_id,
        action=action,
    )


@router.post("/actions", response_model=ActionJobResponse)
async def create_action(
    request: CreateActionRequest,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    if request.target_type not in {"agent", "dc"}:
        raise HTTPException(status_code=400, detail="target_type must be 'agent' or 'dc'")

    action_policy = _policy_for(request.target_type, request.action_type)
    approval_required = bool(action_policy.get("approval", False))
    if request.require_approval is not None:
        approval_required = bool(request.require_approval)

    rollback_action, rollback_payload = _build_rollback(action_policy, request.payload)
    status = "pending_approval" if approval_required else "queued"
    approval_status = "pending" if approval_required else "not_required"

    conn = get_db_connection()
    try:
        target_table = _node_table(request.target_type)
        target_exists = conn.execute(f"SELECT id FROM {target_table} WHERE id = ?", (request.target_id,)).fetchone()
        if not target_exists:
            raise HTTPException(status_code=404, detail=f"Unknown {request.target_type} target")

        action_id = _new_id("act")
        now = _now_iso()
        conn.execute(
            """
            INSERT INTO action_jobs (
                id, target_type, target_id, action_type, payload_json,
                status, approval_required, approval_status,
                requested_by, reason,
                rollback_action_type, rollback_payload_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                request.target_type,
                request.target_id,
                request.action_type,
                json.dumps(request.payload),
                status,
                1 if approval_required else 0,
                approval_status,
                request.requested_by,
                request.reason,
                rollback_action,
                json.dumps(rollback_payload) if rollback_payload is not None else None,
                now,
                now,
            ),
        )
        _audit(
            conn,
            action_id,
            "created",
            request.requested_by,
            {
                "action_type": request.action_type,
                "target_type": request.target_type,
                "target_id": request.target_id,
                "approval_required": approval_required,
            },
        )
        conn.commit()
        row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
    finally:
        conn.close()

    if not approval_required:
        await _dispatch_queued_action(row["id"])

    return _action_row_to_response(row)


@router.post("/actions/{action_id}/approve", response_model=ActionJobResponse)
async def approve_action(
    action_id: str,
    request: ApproveActionRequest,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")

        if not bool(row["approval_required"]):
            raise HTTPException(status_code=400, detail="Action does not require approval")

        now = _now_iso()
        approved_int = 1 if request.approved else 0
        conn.execute(
            "INSERT INTO action_approvals (action_id, approved_by, approved, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (action_id, request.approved_by, approved_int, request.note, now),
        )

        if request.approved:
            conn.execute(
                "UPDATE action_jobs SET status = 'queued', approval_status = 'approved', updated_at = ? WHERE id = ?",
                (now, action_id),
            )
            _audit(conn, action_id, "approved", request.approved_by, {"note": request.note})
        else:
            conn.execute(
                "UPDATE action_jobs SET status = 'cancelled', approval_status = 'rejected', updated_at = ?, completed_at = ? WHERE id = ?",
                (now, now, action_id),
            )
            _audit(conn, action_id, "rejected", request.approved_by, {"note": request.note})

        conn.commit()
        updated = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
    finally:
        conn.close()

    if request.approved:
        await _dispatch_queued_action(action_id)
    return _action_row_to_response(updated)


@router.post("/actions/{action_id}/rollback", response_model=ActionJobResponse)
async def rollback_action(
    action_id: str,
    request: RollbackActionRequest,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")

        rollback_action_type = row["rollback_action_type"]
        rollback_payload_json = row["rollback_payload_json"]
        if not rollback_action_type:
            raise HTTPException(status_code=400, detail="No rollback action defined")

        rollback_payload = json.loads(rollback_payload_json) if rollback_payload_json else {}
        rollback_id = _new_id("act")
        now = _now_iso()
        conn.execute(
            """
            INSERT INTO action_jobs (
                id, target_type, target_id, action_type, payload_json,
                status, approval_required, approval_status,
                requested_by, reason,
                rollback_of_action_id,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'queued', 0, 'not_required', ?, ?, ?, ?, ?)
            """,
            (
                rollback_id,
                row["target_type"],
                row["target_id"],
                rollback_action_type,
                json.dumps(rollback_payload),
                request.requested_by,
                request.reason,
                action_id,
                now,
                now,
            ),
        )
        _audit(conn, action_id, "rollback_requested", request.requested_by, {"rollback_action_id": rollback_id})
        _audit(conn, rollback_id, "created", request.requested_by, {"rollback_of": action_id})
        conn.commit()
        rollback_row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (rollback_id,)).fetchone()
    finally:
        conn.close()

    await _dispatch_queued_action(rollback_id)
    return _action_row_to_response(rollback_row)


@router.get("/actions", response_model=list[ActionJobResponse])
def list_actions(
    limit: int = 200,
    status: Optional[str] = None,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        if status:
            rows = conn.execute(
                "SELECT * FROM action_jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM action_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_action_row_to_response(row) for row in rows]
    finally:
        conn.close()


@router.get("/actions/{action_id}", response_model=ActionJobResponse)
def get_action(
    action_id: str,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")
        return _action_row_to_response(row)
    finally:
        conn.close()


@router.get("/actions/{action_id}/audit")
def get_action_audit(
    action_id: str,
    limit: int = 200,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, action_id, event_type, actor, details_json, created_at
            FROM action_audit_logs
            WHERE action_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (action_id, limit),
        ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.get("details_json") or "{}")
            except Exception:
                item["details"] = {"raw": item.get("details_json")}
            results.append(item)
        return results
    finally:
        conn.close()


@router.post("/actions/{action_id}/status", response_model=ActionJobResponse)
def update_action_status(action_id: str, request: ActionStatusUpdateRequest):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")

        target_type = row["target_type"]
        target_id = row["target_id"]
        if not _validate_node_token(conn, target_type, target_id, request.auth_token):
            raise HTTPException(status_code=401, detail="Invalid node token")

        now = _now_iso()
        completed_at = now if request.status in {"succeeded", "failed", "cancelled"} else None
        conn.execute(
            """
            UPDATE action_jobs
            SET status = ?, result_json = ?, updated_at = ?, completed_at = COALESCE(?, completed_at)
            WHERE id = ?
            """,
            (request.status, json.dumps(request.result), now, completed_at, action_id),
        )
        _audit(conn, action_id, "status_update", target_id, {"status": request.status, "result": request.result})
        conn.commit()

        updated = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        return _action_row_to_response(updated)
    finally:
        conn.close()


@router.websocket("/ws/control/{node_type}/{node_id}")
async def control_ws(websocket: WebSocket, node_type: str, node_id: str, token: str):
    if node_type not in {"agent", "dc"}:
        await websocket.close(code=1008)
        return

    conn = get_db_connection()
    try:
        if not _validate_node_token(conn, node_type, node_id, token):
            await websocket.close(code=1008)
            return
    finally:
        conn.close()

    await registry.connect(node_type, node_id, websocket)
    _mark_node_status(node_type, node_id, "online")
    await _dispatch_pending(node_type, node_id)

    try:
        while True:
            message = await websocket.receive_json()
            msg_type = message.get("type")
            if msg_type == "ping":
                await websocket.send_json({"type": "pong", "ts": _now_iso()})
            elif msg_type == "hello":
                await websocket.send_json({"type": "hello_ack", "node_id": node_id, "node_type": node_type})
            else:
                await websocket.send_json({"type": "ack", "received": msg_type or "unknown"})
    except WebSocketDisconnect:
        registry.disconnect(node_type, node_id)
        _mark_node_status(node_type, node_id, "offline")
