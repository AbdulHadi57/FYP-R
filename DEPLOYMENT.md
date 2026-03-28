# AegisNet Cloud Deployment Guide

This guide describes how to run the distributed **AegisNet Cloud** architecture.

## Architecture Overview
- **Server**: Hosts the centralized Backend (API + Detection Engine) and the Frontend Dashboard.
- **Agent**: Lightweight sensor running on remote nodes; captures traffic and sends features to the Server.

---

## 1. Server Setup (Backend + Frontend)

### A. Backend (API & Detection)
The backend requires Python 3.10+.

1. Navigate to the cloud directory:
   ```bash
   cd /home/kali/FYP-Dashboard/AegisNet-Cloud/cloud
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   # You also need the machine learning libraries used by detection.py
   pip install scikit-learn pandas numpy joblib
   ```

3. Start the API Server:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```
   *The API will be available at `http://localhost:8000`.*

### B. Frontend (Dashboard)
The frontend requires Node.js 18+.

1. Navigate to the frontend directory:
   ```bash
   cd /home/kali/FYP-Dashboard/AegisNet-Cloud/frontend
   ```

2. Install Node dependencies:
   ```bash
   npm install
   ```

3. Start the Development Server:
   ```bash
   npm run dev
   ```
   *The Dashboard will be available at `http://localhost:5173`.*

---

## 2. Agent Setup (Remote Sensor)

Run this on any machine you want to monitor. It acts as a "Thin Client", sending data to the Server.

1. Navigate to the agent directory:
   ```bash
   cd /home/kali/FYP-Dashboard/AegisNet-Cloud/agent
   ```

2. Install Agent dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the Agent:
   *Note: Requires `sudo` (root) permissions to capture network traffic.*
   ```bash
   sudo python3 run_agent.py --interface eth0
   ```

4. (Recommended) Register with control-plane metadata:
   ```bash
   sudo python3 run_agent.py --interface eth0 --server http://<cloud-ip>:8000 --domain corp.local --dc-hint dc01.corp.local
   ```

   *By default, the Agent sends data to `http://localhost:8000/api/ingest`. To change this, edit `PipelineStorage.api_url` in `agent/aegisnet_pipeline/storage.py`.*

---

## Verification
1. Open the Dashboard (`http://localhost:5173`).
2. Generate traffic on the Agent machine (e.g., `curl google.com`).
3. You should see "Live Feed" activity in the Dashboard.

---

## 3. Domain Controller Runner (Single Process)

Run this on each AD/DC node so cloud can issue response actions over a persistent channel.

```bash
cd /home/kali/FYP-Dashboard/AegisNet-Cloud/agent
python3 run_dc_runner.py
```

The runner now starts in interactive mode by default and prompts for required fields (server, domain, FQDN, etc.).

The runner will:
- register the DC (`/api/control/register/dc`)
- send periodic heartbeat (`/api/control/heartbeat/dc/{id}`)
- keep an active websocket channel for command dispatch (`/api/control/ws/control/dc/{id}`)
- execute `isolate_host` / `restore_host` directly in-process when webhook mode is not configured

You can still run non-interactive with explicit flags:

```bash
python3 run_dc_runner.py --non-interactive --server http://<cloud-ip>:8000 --domain corp.local --fqdn dc01.corp.local --site HQ
```

---

## 4. Phase 3 Response Workflow (Approval + Rollback)

### A. Create an Action
Example: block IP on an Agent.

```bash
curl -X POST http://localhost:8000/api/control/actions \
   -H "Content-Type: application/json" \
   -d '{
      "target_type": "agent",
      "target_id": "agt_xxxxxxxx",
      "action_type": "block_ip",
      "payload": {"ip": "10.10.10.20"},
      "requested_by": "analyst1",
      "reason": "C2 callback detected"
   }'
```

If action policy requires approval, it is created as `pending_approval`.

### B. Approve or Reject

```bash
curl -X POST http://localhost:8000/api/control/actions/<action_id>/approve \
   -H "Content-Type: application/json" \
   -d '{"approved_by": "soc_lead", "approved": true, "note": "validated IOC"}'
```

Approved actions move to `queued` and are dispatched over websocket when target is online.

### C. Rollback
If action has rollback metadata, create rollback action:

```bash
curl -X POST http://localhost:8000/api/control/actions/<action_id>/rollback \
   -H "Content-Type: application/json" \
   -d '{"requested_by": "analyst1", "reason": "false positive"}'
```

### D. Inspect status/audit
- `GET /api/control/actions`
- `GET /api/control/actions/{action_id}`
- `GET /api/control/actions/{action_id}/audit`

---

## 5. AD-Local Response Webhook (Optional Compatibility Mode)

This is optional. Use it only if you want a separate local response microservice instead of direct in-process execution in `run_dc_runner.py`.

Run the response service on the Domain Controller VM, then have the DC runner call it locally.

```bash
cd /home/kali/FYP-Dashboard/AegisNet-Cloud/agent
pip install -r requirements.txt
export AEGIS_DOMAIN="aegisnet.local"
export AEGIS_ADMIN_USER="AegisResponseAdmin@aegisnet.local"
export AEGIS_ADMIN_PASS="<strong-password>"
export AEGIS_DC_IP="10.0.2.10"
python3 ad_response_webhook.py
```

Start DC runner to use this local webhook:

```bash
python3 run_dc_runner.py --non-interactive --server http://<cloud-ip>:8000 --domain aegisnet.local --fqdn dc01.aegisnet.local --response-url http://127.0.0.1:5000/webhook
```

Create isolate/restore actions for the DC target:

```bash
curl -X POST http://localhost:8000/api/control/actions \
   -H "Content-Type: application/json" \
   -d '{
      "target_type": "dc",
      "target_id": "dc_xxxxxxxx",
      "action_type": "isolate_host",
      "payload": {"target_ip": "10.0.2.25"},
      "requested_by": "analyst1",
      "reason": "Containment"
   }'
```

Use `action_type: "restore_host"` with the same payload to restore connectivity.

---

## 6. Server-Side Response Templates (Recommended for Scale)

For many agents, keep response logic centrally on cloud and dispatch using `agent_id`.
Cloud resolves the responsible DC for that agent, then sends the action to the DC runner.

### A. Create or Update a Template on Cloud

```bash
curl -X POST http://localhost:8000/api/control/responses/templates \
   -H "Content-Type: application/json" \
   -d '{
      "name": "containment_quarantine",
      "description": "Default host containment using mapped DC",
      "target_action_type": "isolate_host",
      "default_payload": {"mode": "forensic"},
      "require_approval": true,
      "enabled": true
   }'
```

### B. Dispatch by Agent ID (Cloud selects DC)

```bash
curl -X POST http://localhost:8000/api/control/responses/dispatch \
   -H "Content-Type: application/json" \
   -d '{
      "template_name": "containment_quarantine",
      "agent_id": "agt_xxxxxxxx",
      "target_ip": "10.0.2.25",
      "target_port": 443,
      "protocol": "tcp",
      "payload_overrides": {"ticket": "INC-1042"},
      "requested_by": "analyst1",
      "reason": "Automated containment from cloud template"
   }'
```

### C. List Templates

- `GET /api/control/responses/templates`

---

## 7. Control API Key (Recommended)

To protect operator endpoints (`/api/control/actions*`, `/api/control/responses/*`, `/api/control/agents`, `/api/control/dcs`), set:

```bash
export AEGIS_CONTROL_API_KEY="<long-random-key>"
```

Then include header in requests:

```bash
-H "X-Control-Key: <long-random-key>"
```

Dashboard includes a Control Plane tab where this key can be entered and stored locally.
