from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import platform
import re
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
    ad_admin_user: Optional[str] = None
    ad_admin_pass: Optional[str] = None
    dc_ip: Optional[str] = None


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
        self._ws_404_logged_once = False

    def _load_websockets_module(self):
        try:
            return importlib.import_module("websockets")
        except Exception:
            self.logger.error("Package 'websockets' is required for control channel operation")
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
                detail = resp.text
                try:
                    detail = resp.json().get("detail", detail)
                except Exception:
                    pass
                self.logger.error("Registration failed: %s %s", resp.status_code, detail)
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

    def _heartbeat_payload(self, status: str = "online") -> Dict[str, Any]:
        return {
            "auth_token": self.auth_token,
            "status": status,
            "payload": {
                "timestamp": datetime.now(UTC).isoformat(),
                "node_type": self.config.node_type,
                "hostname": self.config.hostname,
                **self.config.metadata,
            },
        }

    def _send_heartbeat(self, status: str) -> None:
        if not self.node_id or not self.auth_token:
            return
        endpoint = (
            f"/api/control/heartbeat/agent/{self.node_id}"
            if self.config.node_type == "agent"
            else f"/api/control/heartbeat/dc/{self.node_id}"
        )
        requests.post(
            f"{self.base_url}{endpoint}",
            json=self._heartbeat_payload(status=status),
            timeout=10,
        )

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat("online")
            except Exception as exc:
                self.logger.warning("Heartbeat failed: %s", exc)
            self._stop_event.wait(self.config.heartbeat_interval)

    def _to_ws_url(self, path: str) -> str:
        if self.base_url.startswith("https://"):
            return "wss://" + self.base_url[len("https://") :] + path
        return "ws://" + self.base_url[len("http://") :] + path

    def _ws_path_candidates(self) -> list[str]:
        if not self.ws_path:
            return []

        primary = self.ws_path
        candidates = [primary]

        if primary.startswith("/api/"):
            candidates.append(primary[len("/api") :])
        else:
            candidates.append(f"/api{primary}" if primary.startswith("/") else f"/api/{primary}")

        # Preserve order while removing duplicates.
        seen = set()
        unique = []
        for item in candidates:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

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

    def _process_action(self, action: Dict[str, Any]) -> None:
        action_id = action.get("id")
        if not action_id:
            return
        self._report_action_status(action_id, "running", {"message": "Action execution started"})
        status, result = self._execute_action(action)
        self._report_action_status(action_id, status, result)

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

    def _validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except Exception:
            return False

    def _fingerprint_os(self, target_ip: str) -> Optional[str]:
        try:
            ping_count_flag = "-n" if platform.system().lower() == "windows" else "-c"
            proc = subprocess.Popen(["ping", ping_count_flag, "1", target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = proc.communicate(timeout=8)
            output = stdout.decode("utf-8", errors="ignore")

            ttl_match = re.search(r"TTL=(\d+)|ttl=(\d+)", output, re.IGNORECASE)
            if not ttl_match:
                return None

            ttl_value = int(ttl_match.group(1) if ttl_match.group(1) else ttl_match.group(2))
            if ttl_value <= 64:
                return "linux"
            if ttl_value <= 128:
                return "windows"
            return "windows"
        except Exception:
            return None

    def _get_dc_response_credentials(self) -> tuple[Optional[str], Optional[str], Optional[str]]:
        admin_user = self.config.ad_admin_user or os.getenv("AEGIS_ADMIN_USER")
        admin_pass = self.config.ad_admin_pass or os.getenv("AEGIS_ADMIN_PASS")
        dc_ip = self.config.dc_ip or os.getenv("AEGIS_DC_IP")
        return admin_user, admin_pass, dc_ip

    def _direct_isolate_windows(self, target_ip: str, admin_user: str, admin_pass: str, dc_ip: Optional[str]) -> tuple[str, Dict[str, Any]]:
        try:
            import winrm  # Lazy import so runner can still operate without this dependency until needed.
        except Exception as exc:
            return "failed", {"message": f"pywinrm is required for windows isolate/restore: {exc}"}

        try:
            session = winrm.Session(f"http://{target_ip}:5985/wsman", auth=(admin_user, admin_pass), transport="ntlm")
            session.run_ps("whoami")

            allow_dc_in = f"New-NetFirewallRule -DisplayName 'AegisNet-Forensic-In' -Direction Inbound -Action Allow -RemoteAddress {dc_ip}" if dc_ip else ""
            allow_dc_out = f"New-NetFirewallRule -DisplayName 'AegisNet-Forensic-Out' -Direction Outbound -Action Allow -RemoteAddress {dc_ip}" if dc_ip else ""
            ps_script = f"""
            {allow_dc_in}
            {allow_dc_out}
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
            """
            result = session.run_ps(ps_script)
            ok = result.status_code == 0
            return (
                "succeeded" if ok else "failed",
                {
                    "status_code": result.status_code,
                    "stdout": (result.std_out or b"").decode("utf-8", errors="ignore").strip(),
                    "stderr": (result.std_err or b"").decode("utf-8", errors="ignore").strip(),
                },
            )
        except Exception as exc:
            return "failed", {"message": f"Windows isolate failed: {exc}"}

    def _direct_restore_windows(self, target_ip: str, admin_user: str, admin_pass: str) -> tuple[str, Dict[str, Any]]:
        try:
            import winrm
        except Exception as exc:
            return "failed", {"message": f"pywinrm is required for windows isolate/restore: {exc}"}

        try:
            session = winrm.Session(f"http://{target_ip}:5985/wsman", auth=(admin_user, admin_pass), transport="ntlm")
            check_result = session.run_ps("Get-NetFirewallRule -DisplayName 'AegisNet-Forensic-In' -ErrorAction SilentlyContinue")
            if not check_result.std_out:
                return "succeeded", {"message": "restore skipped; host is not currently isolated"}

            ps_script = """
            Remove-NetFirewallRule -DisplayName 'AegisNet-Forensic-In' -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName 'AegisNet-Forensic-Out' -ErrorAction SilentlyContinue
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
            """
            result = session.run_ps(ps_script)
            ok = result.status_code == 0
            return (
                "succeeded" if ok else "failed",
                {
                    "status_code": result.status_code,
                    "stdout": (result.std_out or b"").decode("utf-8", errors="ignore").strip(),
                    "stderr": (result.std_err or b"").decode("utf-8", errors="ignore").strip(),
                },
            )
        except Exception as exc:
            return "failed", {"message": f"Windows restore failed: {exc}"}

    def _direct_isolate_linux(self, target_ip: str, admin_user: str, admin_pass: str, dc_ip: Optional[str]) -> tuple[str, Dict[str, Any]]:
        try:
            import paramiko  # Lazy import so non-linux response paths still run.
        except Exception as exc:
            return "failed", {"message": f"paramiko is required for linux isolate/restore: {exc}"}

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=target_ip, username=admin_user, password=admin_pass, timeout=10)

            commands = []
            if dc_ip:
                commands.extend([
                    f"sudo iptables -I INPUT 1 -s {dc_ip} -j ACCEPT -m comment --comment 'AegisNet-Allow-DC-In'",
                    f"sudo iptables -I OUTPUT 1 -d {dc_ip} -j ACCEPT -m comment --comment 'AegisNet-Allow-DC-Out'",
                ])
            commands.extend([
                "sudo iptables -A INPUT -j DROP -m comment --comment 'AegisNet-Isolate-In'",
                "sudo iptables -A OUTPUT -j DROP -m comment --comment 'AegisNet-Isolate-Out'",
            ])
            cmd = "\n".join(commands)
            _, stdout, stderr = ssh.exec_command(cmd)
            stdout_text = stdout.read().decode("utf-8", errors="ignore").strip()
            stderr_text = stderr.read().decode("utf-8", errors="ignore").strip()
            ssh.close()

            ok = stderr_text == ""
            return "succeeded" if ok else "failed", {"stdout": stdout_text, "stderr": stderr_text}
        except Exception as exc:
            return "failed", {"message": f"Linux isolate failed: {exc}"}

    def _direct_restore_linux(self, target_ip: str, admin_user: str, admin_pass: str, dc_ip: Optional[str]) -> tuple[str, Dict[str, Any]]:
        try:
            import paramiko
        except Exception as exc:
            return "failed", {"message": f"paramiko is required for linux isolate/restore: {exc}"}

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=target_ip, username=admin_user, password=admin_pass, timeout=10)

            _, stdout_check, _ = ssh.exec_command("sudo iptables -S | grep 'AegisNet-Isolate-In'")
            has_rule = stdout_check.read().decode("utf-8", errors="ignore").strip()
            if not has_rule:
                ssh.close()
                return "succeeded", {"message": "restore skipped; host is not currently isolated"}

            commands = [
                "sudo iptables -D INPUT -j DROP -m comment --comment 'AegisNet-Isolate-In' 2>/dev/null",
                "sudo iptables -D OUTPUT -j DROP -m comment --comment 'AegisNet-Isolate-Out' 2>/dev/null",
            ]
            if dc_ip:
                commands.extend([
                    f"sudo iptables -D INPUT -s {dc_ip} -j ACCEPT -m comment --comment 'AegisNet-Allow-DC-In' 2>/dev/null",
                    f"sudo iptables -D OUTPUT -d {dc_ip} -j ACCEPT -m comment --comment 'AegisNet-Allow-DC-Out' 2>/dev/null",
                ])

            cmd = "\n".join(commands)
            _, stdout, stderr = ssh.exec_command(cmd)
            stdout_text = stdout.read().decode("utf-8", errors="ignore").strip()
            stderr_text = stderr.read().decode("utf-8", errors="ignore").strip()
            ssh.close()

            ok = stderr_text == ""
            return "succeeded" if ok else "failed", {"stdout": stdout_text, "stderr": stderr_text}
        except Exception as exc:
            return "failed", {"message": f"Linux restore failed: {exc}"}

    def _execute_direct_dc_host_response(self, action_type: str, payload: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        target_ip = str(payload.get("target_ip") or payload.get("ip") or "").strip()
        if not target_ip:
            return "failed", {"message": "Missing payload.target_ip"}
        if not self._validate_ip(target_ip):
            return "failed", {"message": "Invalid target_ip format"}

        admin_user, admin_pass, dc_ip = self._get_dc_response_credentials()
        if not admin_user or not admin_pass:
            return "failed", {
                "message": (
                    "Missing AD admin credentials for direct host response. "
                    "Provide --admin-user/--admin-pass or set AEGIS_ADMIN_USER/AEGIS_ADMIN_PASS."
                )
            }

        os_hint = str(payload.get("target_os") or "").strip().lower()
        os_type = os_hint if os_hint in {"windows", "linux"} else self._fingerprint_os(target_ip)
        if os_type not in {"windows", "linux"}:
            return "failed", {"message": "Host unreachable or OS could not be detected"}

        if action_type == "isolate_host":
            if os_type == "windows":
                return self._direct_isolate_windows(target_ip, admin_user, admin_pass, dc_ip)
            return self._direct_isolate_linux(target_ip, admin_user, admin_pass, dc_ip)

        if action_type == "restore_host":
            if os_type == "windows":
                return self._direct_restore_windows(target_ip, admin_user, admin_pass)
            return self._direct_restore_linux(target_ip, admin_user, admin_pass, dc_ip)

        return "failed", {"message": f"Unsupported direct response action: {action_type}"}

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
            target_ip = payload.get("target_ip") or payload.get("ip")

            if not target_ip:
                return "failed", {"message": "Missing payload.target_ip"}

            return self._execute_direct_dc_host_response(action_type, payload)

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

        ws_paths = self._ws_path_candidates()
        ws_index = 0
        while not self._stop_event.is_set():
            ws_path = ws_paths[ws_index]
            ws_url = self._to_ws_url(f"{ws_path}?token={self.auth_token}")
            try:
                async with self._websockets_module.connect(ws_url, ping_interval=20, ping_timeout=20) as websocket:
                    self._ws_404_logged_once = False
                    await websocket.send(
                        json.dumps({"type": "hello", "node_id": self.node_id, "node_type": self.config.node_type})
                    )
                    while not self._stop_event.is_set():
                        raw = await asyncio.wait_for(websocket.recv(), timeout=30)
                        msg = json.loads(raw)
                        if msg.get("type") == "action":
                            action = msg.get("payload", {})
                            self._process_action(action)
                        elif msg.get("type") == "pong":
                            continue
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                exc_text = str(exc)
                if "404" in exc_text and len(ws_paths) > 1:
                    ws_index = (ws_index + 1) % len(ws_paths)
                    if not self._ws_404_logged_once:
                        self.logger.warning(
                            "Control websocket path returned 404 (%s). Retrying alternate path %s in 5s.",
                            exc,
                            ws_paths[ws_index],
                        )
                        self._ws_404_logged_once = True
                else:
                    self.logger.warning("Control websocket disconnected (%s). Reconnecting in 5s...", exc)
                await asyncio.sleep(5)

    def _ws_thread_main(self) -> None:
        asyncio.run(self._ws_loop())

    def start(self) -> bool:
        if self._websockets_module is None:
            self.logger.error("Cannot start control client without 'websockets' dependency")
            return False

        if not self.register():
            return False

        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        self._ws_thread = threading.Thread(target=self._ws_thread_main, daemon=True)
        self._ws_thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=2)
        try:
            self._send_heartbeat("offline")
        except Exception as exc:
            self.logger.warning("Failed to send offline heartbeat: %s", exc)
