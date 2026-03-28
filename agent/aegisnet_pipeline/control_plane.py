from __future__ import annotations

import asyncio
import json
import logging
import platform
import shutil
import socket
import subprocess
import threading
import time
import importlib
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any, Dict, Optional

import requests


@dataclass
class ControlPlaneConfig:
    server_url: str
    node_type: str  # agent | dc
    enrollment_id: Optional[str] = None
    enrollment_token: Optional[str] = None
    hostname: str = field(default_factory=socket.gethostname)
    domain_fqdn: Optional[str] = None
    dc_hint: Optional[str] = None
    heartbeat_interval: int = 15
    capabilities: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    response_webhook_url: Optional[str] = None


class NodeControlClient:
    """Phase 1 + 2 client: registration/heartbeat plus persistent websocket command channel."""

    def __init__(self, config: ControlPlaneConfig):
        self.config = config
        self.logger = logging.getLogger("AegisNet.ControlClient")
        self.base_url = config.server_url.rstrip("/")
        self.node_id: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.ws_path: Optional[str] = None

        self._stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._websockets_module = self._load_websockets_module()

    def _load_websockets_module(self):
        try:
            return importlib.import_module("websockets")
        except Exception:
            self.logger.warning("Package 'websockets' is not installed; persistent control channel disabled")
            return None

    def _register_payload(self) -> Dict[str, Any]:
        common = {
            "hostname": self.config.hostname,
            "domain_fqdn": self.config.domain_fqdn,
            "capabilities": self.config.capabilities,
        }
        common.update(self.config.metadata)

        if self.config.node_type == "agent":
            common.update(
                {
                    "agent_id": self.config.enrollment_id,
                    "os_type": platform.system(),
                    "os_version": platform.version(),
                    "agent_version": "0.2.0",
                    "dc_hint": self.config.dc_hint,
                    "interfaces": list(self.config.metadata.get("interfaces", [])),
                }
            )
        else:
            common.update(
                {
                    "dc_id": self.config.enrollment_id,
                    "fqdn": self.config.metadata.get("fqdn"),
                    "forest_fqdn": self.config.metadata.get("forest_fqdn"),
                    "site_name": self.config.metadata.get("site_name"),
                    "os_version": platform.version(),
                    "runner_version": "0.2.0",
                }
            )
        return common

    def register(self) -> bool:
        endpoint = "/api/control/register/agent" if self.config.node_type == "agent" else "/api/control/register/dc"
        try:
            resp = requests.post(f"{self.base_url}{endpoint}", json=self._register_payload(), timeout=10)
            if resp.status_code != 200:
                self.logger.error("Registration failed: %s %s", resp.status_code, resp.text)
                return False
            data = resp.json()
            self.node_id = data["node_id"]
            self.auth_token = data["auth_token"]
            self.ws_path = data["websocket_path"]
            self.config.heartbeat_interval = int(data.get("heartbeat_interval_seconds", self.config.heartbeat_interval))
            self.logger.info("Registered %s as %s", self.config.node_type, self.node_id)
            return True
        except Exception as exc:
            self.logger.error("Registration error: %s", exc)
            return False

    def _heartbeat_payload(self) -> Dict[str, Any]:
        return {
            "auth_token": self.auth_token,
            "status": "online",
            "payload": {
                "timestamp": datetime.now(UTC).isoformat(),
                "node_type": self.config.node_type,
                "hostname": self.config.hostname,
                **self.config.metadata,
            },
        }

    def _heartbeat_loop(self) -> None:
        endpoint = (
            f"/api/control/heartbeat/agent/{self.node_id}"
            if self.config.node_type == "agent"
            else f"/api/control/heartbeat/dc/{self.node_id}"
        )
        while not self._stop_event.is_set():
            try:
                requests.post(
                    f"{self.base_url}{endpoint}",
                    json=self._heartbeat_payload(),
                    timeout=10,
                )
            except Exception as exc:
                self.logger.warning("Heartbeat failed: %s", exc)
            self._stop_event.wait(self.config.heartbeat_interval)

    def _to_ws_url(self, path: str) -> str:
        if self.base_url.startswith("https://"):
            return "wss://" + self.base_url[len("https://") :] + path
        return "ws://" + self.base_url[len("http://") :] + path

    def _report_action_status(self, action_id: str, status: str, result: Dict[str, Any]) -> None:
        if not self.auth_token:
            return
        try:
            requests.post(
                f"{self.base_url}/api/control/actions/{action_id}/status",
                json={"auth_token": self.auth_token, "status": status, "result": result},
                timeout=10,
            )
        except Exception as exc:
            self.logger.error("Failed to report action %s status: %s", action_id, exc)

    def _run_command(self, cmd: list[str], timeout: int = 20) -> Dict[str, Any]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "").strip(),
                "stderr": (proc.stderr or "").strip(),
                "command": cmd,
            }
        except Exception as exc:
            return {"returncode": 1, "stdout": "", "stderr": str(exc), "command": cmd}

    def _powershell_bin(self) -> Optional[str]:
        return shutil.which("powershell") or shutil.which("pwsh")

    def _execute_agent_action(self, action_type: str, payload: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        ip = str(payload.get("ip", "")).strip()
        if action_type in {"block_ip", "unblock_ip"} and not ip:
            return "failed", {"message": "Missing payload.ip"}

        system_name = platform.system().lower()
        if system_name == "windows":
            rule_name = f"AegisNet_Block_{ip}" if ip else "AegisNet_Quarantine"
            if action_type == "block_ip":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}",
                ]
            elif action_type == "unblock_ip":
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ]
            elif action_type == "quarantine_host":
                cmd = [
                    "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound",
                ]
            elif action_type == "unquarantine_host":
                cmd = [
                    "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound",
                ]
            else:
                return "failed", {"message": f"Unsupported agent action: {action_type}"}

            result = self._run_command(cmd)
            return ("succeeded" if result["returncode"] == 0 else "failed", result)

        # Linux-like execution path
        if not shutil.which("iptables"):
            return "failed", {"message": "iptables is not installed on node"}

        if action_type == "block_ip":
            cmd = ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"]
            result = self._run_command(cmd)
            return ("succeeded" if result["returncode"] == 0 else "failed", result)

        if action_type == "unblock_ip":
            cmd = ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"]
            result = self._run_command(cmd)
            return ("succeeded" if result["returncode"] == 0 else "failed", result)

        if action_type == "quarantine_host":
            result_out = self._run_command(["iptables", "-I", "OUTPUT", "-j", "DROP"])
            result_in = self._run_command(["iptables", "-I", "INPUT", "-j", "DROP"])
            success = result_out["returncode"] == 0 and result_in["returncode"] == 0
            return ("succeeded" if success else "failed", {"output_rule": result_out, "input_rule": result_in})

        if action_type == "unquarantine_host":
            result_out = self._run_command(["iptables", "-D", "OUTPUT", "-j", "DROP"])
            result_in = self._run_command(["iptables", "-D", "INPUT", "-j", "DROP"])
            success = result_out["returncode"] == 0 and result_in["returncode"] == 0
            return ("succeeded" if success else "failed", {"output_rule": result_out, "input_rule": result_in})

        return "failed", {"message": f"Unsupported agent action: {action_type}"}

    def _execute_dc_action(self, action_type: str, payload: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        if action_type in {"isolate_host", "restore_host"}:
            webhook_url = self.config.response_webhook_url or payload.get("webhook_url")
            target_ip = payload.get("target_ip") or payload.get("ip")
            if not webhook_url:
                return "failed", {"message": "Missing response webhook URL in config or payload.webhook_url"}
            if not target_ip:
                return "failed", {"message": "Missing payload.target_ip"}

            mapped_action = "isolate" if action_type == "isolate_host" else "restore"
            try:
                resp = requests.post(
                    webhook_url,
                    json={"target_ip": target_ip, "action": mapped_action},
                    timeout=30,
                )
                body = resp.json() if resp.content else {}
                ok = resp.status_code < 400 and body.get("status") in {"success", "skipped"}
                return ("succeeded" if ok else "failed", {"status_code": resp.status_code, "body": body})
            except Exception as exc:
                return "failed", {"message": f"Webhook request failed: {exc}"}

        ps_bin = self._powershell_bin()
        if not ps_bin:
            return "failed", {"message": "PowerShell executable not found"}

        identity = payload.get("identity") or payload.get("user") or payload.get("computer")
        if action_type in {"disable_ad_user", "enable_ad_user", "disable_ad_computer", "enable_ad_computer"} and not identity:
            return "failed", {"message": "Missing identity/user/computer in payload"}

        if action_type == "disable_ad_user":
            script = f"Import-Module ActiveDirectory; Disable-ADAccount -Identity '{identity}'"
        elif action_type == "enable_ad_user":
            script = f"Import-Module ActiveDirectory; Enable-ADAccount -Identity '{identity}'"
        elif action_type == "disable_ad_computer":
            script = f"Import-Module ActiveDirectory; Disable-ADAccount -Identity '{identity}'"
        elif action_type == "enable_ad_computer":
            script = f"Import-Module ActiveDirectory; Enable-ADAccount -Identity '{identity}'"
        else:
            return "failed", {"message": f"Unsupported DC action: {action_type}"}

        cmd = [ps_bin, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]
        result = self._run_command(cmd, timeout=40)
        return ("succeeded" if result["returncode"] == 0 else "failed", result)

    def _execute_action(self, action: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        action_type = action.get("action_type")
        payload_raw = action.get("payload_json") or "{}"
        try:
            payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
        except Exception:
            payload = {"raw_payload": payload_raw}

        # Keep execution safe: allow only non-destructive scaffolding actions by default.
        if action_type in {"ping", "noop"}:
            return "succeeded", {"message": "Command acknowledged", "echo": payload}

        if action_type == "log_message":
            msg = str(payload.get("message", ""))
            self.logger.warning("Remote log_message action: %s", msg)
            return "succeeded", {"message": "Logged message", "logged": msg}

        if self.config.node_type == "agent":
            if action_type in {"block_ip", "unblock_ip", "quarantine_host", "unquarantine_host"}:
                return self._execute_agent_action(action_type, payload)

        if self.config.node_type == "dc":
            if action_type in {
                "isolate_host",
                "restore_host",
                "disable_ad_user",
                "enable_ad_user",
                "disable_ad_computer",
                "enable_ad_computer",
            }:
                return self._execute_dc_action(action_type, payload)

        return "failed", {
            "message": f"Action '{action_type}' is not implemented on this node yet",
            "supported_actions": [
                "ping",
                "noop",
                "log_message",
                "block_ip",
                "unblock_ip",
                "quarantine_host",
                "unquarantine_host",
                "disable_ad_user",
                "enable_ad_user",
                "disable_ad_computer",
                "enable_ad_computer",
                "isolate_host",
                "restore_host",
            ],
        }

    async def _ws_loop(self) -> None:
        if not self.ws_path or not self.auth_token:
            return
        if self._websockets_module is None:
            return

        ws_url = self._to_ws_url(f"{self.ws_path}?token={self.auth_token}")
        while not self._stop_event.is_set():
            try:
                async with self._websockets_module.connect(ws_url, ping_interval=20, ping_timeout=20) as websocket:
                    await websocket.send(
                        json.dumps({"type": "hello", "node_id": self.node_id, "node_type": self.config.node_type})
                    )
                    while not self._stop_event.is_set():
                        raw = await asyncio.wait_for(websocket.recv(), timeout=30)
                        msg = json.loads(raw)
                        if msg.get("type") == "action":
                            action = msg.get("payload", {})
                            action_id = action.get("id")
                            if not action_id:
                                continue
                            self._report_action_status(action_id, "running", {"message": "Action execution started"})
                            status, result = self._execute_action(action)
                            self._report_action_status(action_id, status, result)
                        elif msg.get("type") == "pong":
                            continue
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                self.logger.warning("Control websocket disconnected (%s). Reconnecting in 5s...", exc)
                await asyncio.sleep(5)

    def _ws_thread_main(self) -> None:
        asyncio.run(self._ws_loop())

    def start(self) -> bool:
        if not self.register():
            return False

        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        if self._websockets_module is not None:
            self._ws_thread = threading.Thread(target=self._ws_thread_main, daemon=True)
            self._ws_thread.start()
        else:
            self.logger.warning("Running in phase-1-only mode (heartbeats only) until websockets dependency is installed")
        return True

    def stop(self) -> None:
        self._stop_event.set()
