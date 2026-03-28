from __future__ import annotations

import importlib
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _reload_modules():
    for name in ["control_plane", "database", "models"]:
        if name in sys.modules:
            del sys.modules[name]


def _build_test_client(tmp_path: Path) -> TestClient:
    _reload_modules()
    database = importlib.import_module("database")
    database.DB_PATH = tmp_path / "data" / "test_aegisnet.db"

    control_plane = importlib.import_module("control_plane")
    app = FastAPI()
    app.include_router(control_plane.router)
    return TestClient(app)


def test_phase1_registration_and_inventory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = _build_test_client(tmp_path)

    dc = client.post(
        "/api/control/register/dc",
        json={
            "hostname": "dc01",
            "fqdn": "dc01.corp.local",
            "domain_fqdn": "corp.local",
            "capabilities": {"ad_response": True},
        },
    )
    assert dc.status_code == 200

    agent = client.post(
        "/api/control/register/agent",
        json={
            "hostname": "ws01",
            "os_type": "Windows",
            "domain_fqdn": "corp.local",
            "dc_hint": "dc01.corp.local",
            "capabilities": {"flow_capture": True},
        },
    )
    assert agent.status_code == 200

    agents = client.get("/api/control/agents")
    dcs = client.get("/api/control/dcs")
    assert agents.status_code == 200
    assert dcs.status_code == 200
    assert len(agents.json()) == 1
    assert len(dcs.json()) == 1


def test_phase3_action_lifecycle_and_approval(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = _build_test_client(tmp_path)

    agent = client.post(
        "/api/control/register/agent",
        json={
            "hostname": "host1",
            "os_type": "Linux",
            "capabilities": {"flow_capture": True},
        },
    ).json()

    action = client.post(
        "/api/control/actions",
        json={
            "target_type": "agent",
            "target_id": agent["node_id"],
            "action_type": "block_ip",
            "payload": {"ip": "10.10.10.20"},
            "requested_by": "analyst1",
            "reason": "test",
        },
    )
    assert action.status_code == 200
    action_id = action.json()["id"]
    assert action.json()["status"] == "pending_approval"

    approve = client.post(
        f"/api/control/actions/{action_id}/approve",
        json={"approved_by": "soc_lead", "approved": True, "note": "ok"},
    )
    assert approve.status_code == 200
    assert approve.json()["approval_status"] == "approved"



def test_phase4_template_dispatch_maps_agent_to_dc(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = _build_test_client(tmp_path)

    dc = client.post(
        "/api/control/register/dc",
        json={
            "hostname": "dc01",
            "fqdn": "dc01.corp.local",
            "domain_fqdn": "corp.local",
            "capabilities": {"ad_response": True},
        },
    ).json()

    agent = client.post(
        "/api/control/register/agent",
        json={
            "hostname": "host1",
            "os_type": "Windows",
            "domain_fqdn": "corp.local",
            "dc_hint": "dc01.corp.local",
            "capabilities": {"flow_capture": True},
        },
    ).json()

    save_template = client.post(
        "/api/control/responses/templates",
        json={
            "name": "containment_test",
            "target_action_type": "isolate_host",
            "default_payload": {"mode": "forensic"},
            "require_approval": True,
            "enabled": True,
        },
    )
    assert save_template.status_code == 200

    dispatch = client.post(
        "/api/control/responses/dispatch",
        json={
            "template_name": "containment_test",
            "agent_id": agent["node_id"],
            "target_ip": "10.0.2.25",
            "requested_by": "analyst1",
            "reason": "containment",
        },
    )
    assert dispatch.status_code == 200
    body = dispatch.json()
    assert body["resolved_dc_id"] == dc["node_id"]
    assert body["action"]["target_type"] == "dc"
    assert body["action"]["target_id"] == dc["node_id"]
