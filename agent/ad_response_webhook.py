#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import re
import subprocess
import time

import paramiko
import winrm
from flask import Flask, jsonify, request

app = Flask(__name__)

# Read secrets/config from environment variables instead of hardcoding.
DOMAIN = os.getenv("AEGIS_DOMAIN", "aegisnet.local")
ADMIN_USER = os.getenv("AEGIS_ADMIN_USER", f"AegisResponseAdmin@{DOMAIN}")
ADMIN_PASS = os.getenv("AEGIS_ADMIN_PASS", "")
DC_IP = os.getenv("AEGIS_DC_IP", "10.0.2.10")


def fingerprint_os(target_ip: str):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        process = subprocess.Popen(["ping", param, "1", target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
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


def isolate_windows(target_ip: str) -> str:
    session = winrm.Session(f"http://{target_ip}:5985/wsman", auth=(ADMIN_USER, ADMIN_PASS), transport="ntlm")
    try:
        session.run_ps("whoami")
        ps_script = f"""
        New-NetFirewallRule -DisplayName 'AegisNet-Forensic-In' -Direction Inbound -Action Allow -RemoteAddress {DC_IP}
        New-NetFirewallRule -DisplayName 'AegisNet-Forensic-Out' -Direction Outbound -Action Allow -RemoteAddress {DC_IP}
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
        """
        session.run_ps(ps_script)
        return "success"
    except Exception:
        return "failed"


def restore_windows(target_ip: str) -> str:
    session = winrm.Session(f"http://{target_ip}:5985/wsman", auth=(ADMIN_USER, ADMIN_PASS), transport="ntlm")
    try:
        check_script = "Get-NetFirewallRule -DisplayName 'AegisNet-Forensic-In' -ErrorAction SilentlyContinue"
        result = session.run_ps(check_script)
        if not result.std_out:
            return "not_needed"

        ps_script = """
        Remove-NetFirewallRule -DisplayName 'AegisNet-Forensic-In' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'AegisNet-Forensic-Out' -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        """
        session.run_ps(ps_script)
        return "success"
    except Exception:
        return "failed"


def isolate_linux(target_ip: str) -> str:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=target_ip, username=ADMIN_USER, password=ADMIN_PASS, timeout=10)

        isolation_commands = f"""
        sudo iptables -I INPUT 1 -s {DC_IP} -j ACCEPT
        sudo iptables -I OUTPUT 1 -d {DC_IP} -j ACCEPT
        sudo iptables -A INPUT -j DROP
        sudo iptables -A OUTPUT -j DROP
        """
        ssh.exec_command(isolation_commands)
        ssh.close()
        return "success"
    except Exception:
        return "failed"


def restore_linux(target_ip: str) -> str:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=target_ip, username=ADMIN_USER, password=ADMIN_PASS, timeout=10)

        _, stdout, _ = ssh.exec_command("sudo iptables -S | grep '\\-A INPUT \\-j DROP'")
        rule_exists = stdout.read().decode("utf-8").strip()
        if not rule_exists:
            ssh.close()
            return "not_needed"

        ssh.exec_command("sudo iptables -F")
        ssh.close()
        return "success"
    except Exception:
        return "failed"


@app.route("/health", methods=["GET"])
def health():
    if not ADMIN_PASS:
        return jsonify({"status": "warning", "message": "AEGIS_ADMIN_PASS is not configured"}), 200
    return jsonify({"status": "ok"}), 200


@app.route("/webhook", methods=["POST"])
def handle_alert():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid payload"}), 400

    if not ADMIN_PASS:
        return jsonify({"status": "failed", "message": "AEGIS_ADMIN_PASS is not configured"}), 500

    target_ip = data.get("target_ip")
    action = (data.get("action") or "").lower()
    if not target_ip or action not in {"isolate", "restore"}:
        return jsonify({"status": "failed", "message": "target_ip and action(isolate|restore) required"}), 400

    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[AEGISNET COMMAND] {current_time} target={target_ip} action={action}")

    os_type = fingerprint_os(target_ip)
    if not os_type:
        return jsonify({"status": "failed", "message": "Host unreachable or OS unknown"}), 404

    status_flag = "failed"
    if action == "isolate":
        status_flag = isolate_windows(target_ip) if os_type == "windows" else isolate_linux(target_ip)
    elif action == "restore":
        status_flag = restore_windows(target_ip) if os_type == "windows" else restore_linux(target_ip)

    if status_flag == "success":
        return jsonify({"status": "success", "message": f"{action} completed successfully on {target_ip} ({os_type})"}), 200
    if status_flag == "not_needed":
        return jsonify({"status": "skipped", "message": f"Action skipped for {target_ip}; already in requested state"}), 200
    return jsonify({"status": "failed", "message": "Command failed to execute"}), 500


if __name__ == "__main__":
    print("AegisNet AD response webhook starting on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)
