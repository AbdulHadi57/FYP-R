from __future__ import annotations

import json
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
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
OFFLINE_AFTER_SECONDS = HEARTBEAT_INTERVAL_SECONDS * 3
CONTROL_API_KEY = os.getenv("AEGIS_CONTROL_API_KEY", "").strip()

# Regex for validating IPv4 / IPv6 addresses.
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

# Action policy keeps command surface explicit and auditable.
ACTION_POLICY = {
    "agent": {
        "ping": {"approval": False},
        "noop": {"approval": False},
        "log_message": {"approval": False},
        "block_ip": {"approval": False, "rollback_action": "unblock_ip", "rollback_payload_builder": "same"},
        "unblock_ip": {"approval": False},
        "quarantine_host": {"approval": False, "rollback_action": "unquarantine_host", "rollback_payload_builder": "same"},
        "unquarantine_host": {"approval": False},
    },
    "dc": {
        "ping": {"approval": False},
        "noop": {"approval": False},
        "log_message": {"approval": False},
        "isolate_host": {"approval": False, "rollback_action": "restore_host", "rollback_payload_builder": "same"},
        "restore_host": {"approval": False},
        "disable_ad_user": {"approval": False, "rollback_action": "enable_ad_user", "rollback_payload_builder": "same"},
        "enable_ad_user": {"approval": False},
        "disable_ad_computer": {"approval": False, "rollback_action": "enable_ad_computer", "rollback_payload_builder": "same"},
        "enable_ad_computer": {"approval": False},
    },
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except Exception:
        return None


def _is_stale(last_seen: Optional[str]) -> bool:
    seen_at = _parse_iso(last_seen)
    if not seen_at:
        return True
    return (datetime.now(UTC) - seen_at) > timedelta(seconds=OFFLINE_AFTER_SECONDS)


def _refresh_stale_node_statuses(conn) -> None:
    now = _now_iso()

    agent_rows = conn.execute("SELECT id, status, last_seen FROM agents").fetchall()
    stale_agents = [row["id"] for row in agent_rows if row["status"] != "offline" and _is_stale(row["last_seen"])]
    if stale_agents:
        placeholders = ",".join("?" for _ in stale_agents)
        conn.execute(
            f"UPDATE agents SET status = 'offline', updated_at = ? WHERE id IN ({placeholders})",
            (now, *stale_agents),
        )

    dc_rows = conn.execute("SELECT id, status, last_seen FROM domain_controllers").fetchall()
    stale_dcs = [row["id"] for row in dc_rows if row["status"] != "offline" and _is_stale(row["last_seen"])]
    if stale_dcs:
        placeholders = ",".join("?" for _ in stale_dcs)
        conn.execute(
            f"UPDATE domain_controllers SET status = 'offline', updated_at = ? WHERE id IN ({placeholders})",
            (now, *stale_dcs),
        )

    if stale_agents or stale_dcs:
        conn.commit()


def _validate_ip(ip: str) -> bool:
    """Return True if *ip* looks like a valid IPv4 or IPv6 address."""
    if not ip or len(ip) > 45:
        return False
    return bool(_IPV4_RE.match(ip) or _IPV6_RE.match(ip))


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
compat_router = APIRouter(tags=["control-plane-compat"])


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


def _audit(conn, action_id: str, event_type: str, actor: str, details: dict, target_info: str = None):
    conn.execute(
        """
        INSERT INTO action_audit_logs (action_id, event_type, actor, target_info, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (action_id, event_type, actor, target_info, json.dumps(details), _now_iso()),
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
            _audit(conn, action_id, "dispatched", "control-plane", {"target": row["target_id"]},
                   target_info=row["target_id"])
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
        WHERE b.agent_id = ? AND b.is_active = 1 AND d.approval_status = 'approved'
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
            "SELECT id FROM domain_controllers WHERE (id = ? OR hostname = ? OR fqdn = ?) AND approval_status = 'approved' LIMIT 1",
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
            WHERE domain_fqdn = ? AND approval_status = 'approved'
            ORDER BY CASE WHEN status = 'online' THEN 0 ELSE 1 END, updated_at DESC
            LIMIT 1
            """,
            (domain_fqdn,),
        ).fetchone()
        if dc:
            return dc["id"]

    # 4) Last resort, choose freshest online approved DC.
    dc = conn.execute(
        """
        SELECT id
        FROM domain_controllers
        WHERE approval_status = 'approved'
        ORDER BY CASE WHEN status = 'online' THEN 0 ELSE 1 END, updated_at DESC
        LIMIT 1
        """
    ).fetchone()
    if dc:
        return dc["id"]

    raise HTTPException(status_code=409, detail="No approved domain controller available for this agent")


# ─── Registration ────────────────────────────────────────────────────────────

@router.post("/register/agent", response_model=RegistrationResponse)
def register_agent(request: AgentRegistrationRequest):
    conn = get_db_connection()
    try:
        if not request.agent_id:
            existing_agent = conn.execute(
                """
                SELECT id
                FROM agents
                WHERE LOWER(hostname) = LOWER(?)
                  AND (
                    (? = '' AND COALESCE(domain_fqdn, '') = '')
                    OR (? <> '' AND LOWER(COALESCE(domain_fqdn, '')) = LOWER(?))
                  )
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (
                    request.hostname,
                    (request.domain_fqdn or "").strip(),
                    (request.domain_fqdn or "").strip(),
                    (request.domain_fqdn or "").strip(),
                ),
            ).fetchone()
            if existing_agent:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Agent already enrolled as '{existing_agent['id']}'. "
                        "Reconnect by reusing this agent_id."
                    ),
                )

        # Validate that the agent can register: must have an approved DC
        dc_hint = (request.dc_hint or "").strip()
        domain = (request.domain_fqdn or "").strip()

        approved_dc = None
        if dc_hint:
            approved_dc = conn.execute(
                "SELECT id FROM domain_controllers WHERE (id = ? OR hostname = ? OR fqdn = ?) AND approval_status = 'approved' LIMIT 1",
                (dc_hint, dc_hint, dc_hint),
            ).fetchone()
        if not approved_dc and domain:
            approved_dc = conn.execute(
                "SELECT id FROM domain_controllers WHERE domain_fqdn = ? AND approval_status = 'approved' LIMIT 1",
                (domain,),
            ).fetchone()
        if not approved_dc:
            # Try any approved DC as last resort
            approved_dc = conn.execute(
                "SELECT id FROM domain_controllers WHERE approval_status = 'approved' LIMIT 1"
            ).fetchone()

        if not approved_dc:
            raise HTTPException(
                status_code=403,
                detail="No approved domain controller available. A domain controller must be registered and approved before agents can join.",
            )

        resolved_dc_id = approved_dc["id"]

        node_id = request.agent_id or _new_id("agt")
        token_row = conn.execute("SELECT auth_token FROM agents WHERE id = ?", (node_id,)).fetchone()
        auth_token = token_row["auth_token"] if token_row else _new_token()
        now = _now_iso()

        conn.execute(
            """
            INSERT INTO agents (
                id, hostname, os_type, os_version, agent_version, domain_fqdn, dc_hint, dc_id,
                interfaces_json, capabilities_json, auth_token, status, last_seen, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname,
                os_type=excluded.os_type,
                os_version=excluded.os_version,
                agent_version=excluded.agent_version,
                domain_fqdn=excluded.domain_fqdn,
                dc_hint=excluded.dc_hint,
                dc_id=excluded.dc_id,
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
                resolved_dc_id,
                json.dumps(request.interfaces),
                json.dumps(request.capabilities),
                auth_token,
                now,
                now,
            ),
        )

        # Update binding
        conn.execute("UPDATE agent_dc_bindings SET is_active = 0 WHERE agent_id = ?", (node_id,))
        conn.execute(
            """
            INSERT INTO agent_dc_bindings (agent_id, dc_id, binding_source, is_active)
            VALUES (?, ?, 'auto', 1)
            """,
            (node_id, resolved_dc_id),
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
        if not request.dc_id:
            existing_dc = conn.execute(
                """
                SELECT id
                FROM domain_controllers
                WHERE (
                    LOWER(hostname) = LOWER(?)
                    OR (? <> '' AND LOWER(COALESCE(fqdn, '')) = LOWER(?))
                )
                  AND (
                    (? = '' AND COALESCE(domain_fqdn, '') = '')
                    OR (? <> '' AND LOWER(COALESCE(domain_fqdn, '')) = LOWER(?))
                  )
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (
                    request.hostname,
                    (request.fqdn or "").strip(),
                    (request.fqdn or "").strip(),
                    (request.domain_fqdn or "").strip(),
                    (request.domain_fqdn or "").strip(),
                    (request.domain_fqdn or "").strip(),
                ),
            ).fetchone()
            if existing_dc:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Domain controller already enrolled as '{existing_dc['id']}'. "
                        "Reconnect by reusing this dc_id."
                    ),
                )

        node_id = request.dc_id or _new_id("dc")
        token_row = conn.execute("SELECT auth_token, approval_status FROM domain_controllers WHERE id = ?", (node_id,)).fetchone()
        auth_token = token_row["auth_token"] if token_row else _new_token()
        # Preserve approval_status on re-registration
        existing_approval = token_row["approval_status"] if token_row else "pending"
        now = _now_iso()

        conn.execute(
            """
            INSERT INTO domain_controllers (
                id, hostname, fqdn, domain_fqdn, forest_fqdn, site_name,
                os_version, runner_version, capabilities_json, auth_token,
                approval_status, status, last_seen, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
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
                existing_approval,
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


# ─── DC Approval ─────────────────────────────────────────────────────────────

@router.post("/dcs/{dc_id}/approve")
def approve_dc(
    dc_id: str,
    approved: bool = True,
    approved_by: str = "soc_analyst",
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, approval_status FROM domain_controllers WHERE id = ?", (dc_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Domain controller not found")

        now = _now_iso()
        new_status = "approved" if approved else "rejected"
        conn.execute(
            "UPDATE domain_controllers SET approval_status = ?, approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ?",
            (new_status, approved_by, now, now, dc_id),
        )
        _audit(conn, dc_id, f"dc_{new_status}", approved_by,
               {"dc_id": dc_id, "previous_status": row["approval_status"]},
               target_info=dc_id)
        conn.commit()
        return {"status": "ok", "dc_id": dc_id, "approval_status": new_status}
    finally:
        conn.close()


@router.delete("/dcs/{dc_id}")
def delete_dc(
    dc_id: str,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    """Remove a DC and cascade-remove all agents bound to it."""
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id FROM domain_controllers WHERE id = ?", (dc_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Domain controller not found")

        # Find and remove all agents bound to this DC
        bound_agents = conn.execute(
            "SELECT agent_id FROM agent_dc_bindings WHERE dc_id = ? AND is_active = 1", (dc_id,)
        ).fetchall()
        agent_ids_removed = []
        for agent_row in bound_agents:
            aid = agent_row["agent_id"]
            agent_ids_removed.append(aid)
            conn.execute("DELETE FROM agents WHERE id = ?", (aid,))
            conn.execute("DELETE FROM agent_dc_bindings WHERE agent_id = ?", (aid,))

        # Remove the DC bindings and the DC itself
        conn.execute("DELETE FROM agent_dc_bindings WHERE dc_id = ?", (dc_id,))
        conn.execute("DELETE FROM domain_controllers WHERE id = ?", (dc_id,))

        _audit(conn, dc_id, "dc_deleted", "soc_analyst",
               {"dc_id": dc_id, "cascaded_agents_removed": agent_ids_removed},
               target_info=dc_id)
        conn.commit()
        return {
            "status": "ok",
            "dc_id": dc_id,
            "agents_removed": agent_ids_removed,
            "message": f"DC {dc_id} and {len(agent_ids_removed)} agent(s) removed",
        }
    finally:
        conn.close()


# ─── Heartbeat ───────────────────────────────────────────────────────────────

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


# ─── Listing ─────────────────────────────────────────────────────────────────

@router.get("/agents", response_model=list[NodeSummary])
def list_agents(
    limit: int = 200,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        _refresh_stale_node_statuses(conn)
        rows = conn.execute(
            "SELECT id, hostname, status, last_seen, domain_fqdn, dc_id FROM agents ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [NodeSummary(**dict(row)) for row in rows]
    finally:
        conn.close()


@router.get("/dcs")
def list_dcs(
    limit: int = 200,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        _refresh_stale_node_statuses(conn)
        rows = conn.execute(
            """SELECT id, hostname, status, last_seen, domain_fqdn, approval_status, approved_by, approved_at, fqdn
               FROM domain_controllers ORDER BY updated_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            # Count agents bound to this DC
            agent_count = conn.execute(
                "SELECT COUNT(*) FROM agents WHERE dc_id = ?", (d["id"],)
            ).fetchone()[0]
            d["agent_count"] = agent_count
            results.append(d)
        return results
    finally:
        conn.close()


# ─── Response Templates ─────────────────────────────────────────────────────

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

    # Validate IP
    if request.target_ip and not _validate_ip(request.target_ip):
        raise HTTPException(status_code=400, detail="Invalid target IP address format")

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
            target_info=request.target_ip,
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


# ─── Actions ─────────────────────────────────────────────────────────────────

@router.post("/actions", response_model=ActionJobResponse)
async def create_action(
    request: CreateActionRequest,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    _require_operator_key(x_control_key)
    if request.target_type not in {"agent", "dc"}:
        raise HTTPException(status_code=400, detail="target_type must be 'agent' or 'dc'")

    # Validate IPs in payload
    for ip_key in ("ip", "target_ip"):
        ip_val = request.payload.get(ip_key, "")
        if ip_val and not _validate_ip(str(ip_val)):
            raise HTTPException(status_code=400, detail=f"Invalid IP address in payload.{ip_key}")

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

        target_ip = request.payload.get("target_ip") or request.payload.get("ip") or ""
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
            target_info=target_ip,
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
        target_ip = rollback_payload.get("target_ip") or rollback_payload.get("ip") or ""
        _audit(conn, action_id, "rollback_requested", request.requested_by,
               {"rollback_action_id": rollback_id}, target_info=target_ip)
        _audit(conn, rollback_id, "created", request.requested_by,
               {"rollback_of": action_id}, target_info=target_ip)
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
            SELECT id, action_id, event_type, actor, target_info, details_json, created_at
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


# ─── Unified Audit Trail ────────────────────────────────────────────────────

@router.get("/audit-trail")
def get_audit_trail(
    limit: int = 200,
    action_type: Optional[str] = None,
    x_control_key: Optional[str] = Header(default=None, alias="X-Control-Key"),
):
    """Unified audit trail of all control-plane actions."""
    _require_operator_key(x_control_key)
    conn = get_db_connection()
    try:
        base_query = """
            SELECT a.id, a.action_id, a.event_type, a.actor, a.target_info, a.details_json, a.created_at,
                   j.action_type AS job_action_type, j.target_type AS job_target_type,
                   j.target_id AS job_target_id, j.status AS job_status, j.payload_json AS job_payload_json
            FROM action_audit_logs a
            LEFT JOIN action_jobs j ON a.action_id = j.id
        """
        params = []

        if action_type:
            base_query += " WHERE j.action_type = ?"
            params.append(action_type)

        base_query += " ORDER BY a.created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(base_query, tuple(params)).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.get("details_json") or "{}")
            except Exception:
                item["details"] = {}
            try:
                item["payload"] = json.loads(item.get("job_payload_json") or "{}")
            except Exception:
                item["payload"] = {}
            results.append(item)
        return results
    finally:
        conn.close()


# ─── Action Status Update (from nodes) ──────────────────────────────────────

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
        _audit(conn, action_id, "status_update", target_id,
               {"status": request.status, "result": request.result},
               target_info=target_id)
        conn.commit()

        updated = conn.execute("SELECT * FROM action_jobs WHERE id = ?", (action_id,)).fetchone()
        return _action_row_to_response(updated)
    finally:
        conn.close()


# ─── WebSocket Control Channel ───────────────────────────────────────────────

async def _control_ws_impl(websocket: WebSocket, node_type: str, node_id: str, token: str):
    if node_type not in {"agent", "dc"}:
        await websocket.close(code=1008)
        return

    conn = get_db_connection()
    try:
        if not _validate_node_token(conn, node_type, node_id, token):
            await websocket.close(code=1008)
            return
        # For DCs, check approval status
        if node_type == "dc":
            dc_row = conn.execute("SELECT approval_status FROM domain_controllers WHERE id = ?", (node_id,)).fetchone()
            if dc_row and dc_row["approval_status"] != "approved":
                await websocket.close(code=1008, reason="DC not approved")
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


@router.websocket("/ws/control/{node_type}/{node_id}")
async def control_ws(websocket: WebSocket, node_type: str, node_id: str, token: str):
    await _control_ws_impl(websocket, node_type, node_id, token)


@compat_router.websocket("/control/ws/control/{node_type}/{node_id}")
async def control_ws_compat_prefixed(websocket: WebSocket, node_type: str, node_id: str, token: str):
    await _control_ws_impl(websocket, node_type, node_id, token)


@compat_router.websocket("/ws/control/{node_type}/{node_id}")
async def control_ws_compat_short(websocket: WebSocket, node_type: str, node_id: str, token: str):
    await _control_ws_impl(websocket, node_type, node_id, token)
