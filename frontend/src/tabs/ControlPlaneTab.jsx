import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';

const EMPTY_TEMPLATE_FORM = {
  name: '',
  description: '',
  target_action_type: 'isolate_host',
  default_payload_json: '{}',
  require_approval: true,
  enabled: true,
};

const EMPTY_DISPATCH_FORM = {
  template_name: '',
  agent_id: '',
  target_ip: '',
  target_port: '',
  protocol: 'tcp',
  payload_overrides_json: '{}',
  requested_by: 'analyst1',
  reason: 'Automated containment',
};

function parseJsonOrThrow(raw, fieldName) {
  try {
    return raw && raw.trim() ? JSON.parse(raw) : {};
  } catch {
    throw new Error(`Invalid JSON in ${fieldName}`);
  }
}

export default function ControlPlaneTab() {
  const [apiKey, setApiKey] = useState(localStorage.getItem('aegis.controlApiKey') || '');
  const [agents, setAgents] = useState([]);
  const [dcs, setDcs] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [pendingActions, setPendingActions] = useState([]);
  const [actions, setActions] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [selectedActionId, setSelectedActionId] = useState('');
  const [templateForm, setTemplateForm] = useState(EMPTY_TEMPLATE_FORM);
  const [dispatchForm, setDispatchForm] = useState(EMPTY_DISPATCH_FORM);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const requestHeaders = useMemo(() => {
    if (!apiKey.trim()) {
      return {};
    }
    return { 'X-Control-Key': apiKey.trim() };
  }, [apiKey]);

  const fetchAll = async () => {
    setLoading(true);
    setError('');
    try {
      const [agentsRes, dcsRes, templatesRes, pendingRes, actionsRes] = await Promise.all([
        axios.get('/api/control/agents?limit=200', { headers: requestHeaders }),
        axios.get('/api/control/dcs?limit=200', { headers: requestHeaders }),
        axios.get('/api/control/responses/templates?enabled_only=false&limit=200', { headers: requestHeaders }),
        axios.get('/api/control/actions?status=pending_approval&limit=100', { headers: requestHeaders }),
        axios.get('/api/control/actions?limit=100', { headers: requestHeaders }),
      ]);
      setAgents(agentsRes.data || []);
      setDcs(dcsRes.data || []);
      setTemplates(templatesRes.data || []);
      setPendingActions(pendingRes.data || []);
      setActions(actionsRes.data || []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load control-plane data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
    const timer = setInterval(fetchAll, 8000);
    return () => clearInterval(timer);
  }, [requestHeaders]);

  const submitTemplate = async (e) => {
    e.preventDefault();
    setError('');
    setNotice('');
    try {
      const defaultPayload = parseJsonOrThrow(templateForm.default_payload_json, 'template default payload');
      await axios.post(
        '/api/control/responses/templates',
        {
          name: templateForm.name,
          description: templateForm.description,
          target_action_type: templateForm.target_action_type,
          default_payload: defaultPayload,
          require_approval: templateForm.require_approval,
          enabled: templateForm.enabled,
        },
        { headers: requestHeaders }
      );
      setNotice('Template saved');
      setTemplateForm(EMPTY_TEMPLATE_FORM);
      fetchAll();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Template save failed');
    }
  };

  const submitDispatch = async (e) => {
    e.preventDefault();
    setError('');
    setNotice('');
    try {
      const payloadOverrides = parseJsonOrThrow(dispatchForm.payload_overrides_json, 'dispatch payload overrides');
      const body = {
        template_name: dispatchForm.template_name,
        agent_id: dispatchForm.agent_id,
        target_ip: dispatchForm.target_ip,
        protocol: dispatchForm.protocol,
        payload_overrides: payloadOverrides,
        requested_by: dispatchForm.requested_by,
        reason: dispatchForm.reason,
      };
      if (dispatchForm.target_port) {
        body.target_port = Number(dispatchForm.target_port);
      }

      const res = await axios.post('/api/control/responses/dispatch', body, { headers: requestHeaders });
      setNotice(`Dispatched to DC ${res.data?.resolved_dc_id || 'unknown'}`);
      setDispatchForm((prev) => ({ ...EMPTY_DISPATCH_FORM, requested_by: prev.requested_by }));
      fetchAll();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Template dispatch failed');
    }
  };

  const approveAction = async (actionId, approved) => {
    setError('');
    setNotice('');
    const note = approved ? 'Approved from dashboard' : 'Rejected from dashboard';
    try {
      await axios.post(
        `/api/control/actions/${actionId}/approve`,
        {
          approved_by: dispatchForm.requested_by || 'analyst1',
          approved,
          note,
        },
        { headers: requestHeaders }
      );
      setNotice(`Action ${approved ? 'approved' : 'rejected'}: ${actionId}`);
      fetchAll();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Approval update failed');
    }
  };

  const loadAudit = async (actionId) => {
    setSelectedActionId(actionId);
    setError('');
    try {
      const res = await axios.get(`/api/control/actions/${actionId}/audit?limit=100`, { headers: requestHeaders });
      setAuditLogs(res.data || []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load audit logs');
      setAuditLogs([]);
    }
  };

  return (
    <div className="space-y-6">
      <div className="card p-4 border border-cyan-500/20 bg-black/30">
        <h2 className="text-lg font-semibold text-cyan-300">Control Plane</h2>
        <p className="text-xs text-gray-400 mt-1">Manage templates, dispatch responses, and approve actions.</p>
        <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          <div className="p-3 rounded bg-black/40 border border-white/10">Agents: <span className="text-cyan-300">{agents.length}</span></div>
          <div className="p-3 rounded bg-black/40 border border-white/10">DCs: <span className="text-cyan-300">{dcs.length}</span></div>
          <div className="p-3 rounded bg-black/40 border border-white/10">Pending approvals: <span className="text-orange-300">{pendingActions.length}</span></div>
        </div>
      </div>

      <div className="card p-4 border border-white/10 bg-black/20">
        <label className="block text-xs text-gray-400 mb-1">Control API Key (`X-Control-Key`)</label>
        <div className="flex gap-2">
          <input
            className="flex-1 bg-black/50 border border-white/10 rounded px-3 py-2 text-sm"
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Optional unless backend sets AEGIS_CONTROL_API_KEY"
          />
          <button
            className="px-4 py-2 rounded bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-sm"
            onClick={() => {
              localStorage.setItem('aegis.controlApiKey', apiKey);
              fetchAll();
            }}
          >
            Apply
          </button>
        </div>
      </div>

      {error ? <div className="text-red-300 text-sm">{error}</div> : null}
      {notice ? <div className="text-emerald-300 text-sm">{notice}</div> : null}
      {loading ? <div className="text-gray-400 text-sm">Loading control-plane data...</div> : null}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <form onSubmit={submitTemplate} className="card p-4 border border-white/10 bg-black/20 space-y-3">
          <h3 className="font-semibold text-cyan-300">Template Editor</h3>
          <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Template name" value={templateForm.name} onChange={(e) => setTemplateForm((p) => ({ ...p, name: e.target.value }))} required />
          <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Description" value={templateForm.description} onChange={(e) => setTemplateForm((p) => ({ ...p, description: e.target.value }))} />
          <select className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" value={templateForm.target_action_type} onChange={(e) => setTemplateForm((p) => ({ ...p, target_action_type: e.target.value }))}>
            <option value="isolate_host">isolate_host</option>
            <option value="restore_host">restore_host</option>
            <option value="disable_ad_user">disable_ad_user</option>
            <option value="enable_ad_user">enable_ad_user</option>
            <option value="disable_ad_computer">disable_ad_computer</option>
            <option value="enable_ad_computer">enable_ad_computer</option>
          </select>
          <textarea className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm font-mono" rows={4} placeholder="Default payload JSON" value={templateForm.default_payload_json} onChange={(e) => setTemplateForm((p) => ({ ...p, default_payload_json: e.target.value }))} />
          <div className="flex gap-4 text-sm">
            <label className="flex items-center gap-2"><input type="checkbox" checked={templateForm.require_approval} onChange={(e) => setTemplateForm((p) => ({ ...p, require_approval: e.target.checked }))} />Require approval</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={templateForm.enabled} onChange={(e) => setTemplateForm((p) => ({ ...p, enabled: e.target.checked }))} />Enabled</label>
          </div>
          <button className="px-4 py-2 rounded bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-sm" type="submit">Save Template</button>
        </form>

        <form onSubmit={submitDispatch} className="card p-4 border border-white/10 bg-black/20 space-y-3">
          <h3 className="font-semibold text-cyan-300">Dispatch Template</h3>
          <select className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" value={dispatchForm.template_name} onChange={(e) => setDispatchForm((p) => ({ ...p, template_name: e.target.value }))} required>
            <option value="">Select template</option>
            {templates.map((tpl) => (
              <option key={tpl.id} value={tpl.name}>{tpl.name}</option>
            ))}
          </select>
          <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Agent ID" value={dispatchForm.agent_id} onChange={(e) => setDispatchForm((p) => ({ ...p, agent_id: e.target.value }))} required />
          <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Target IP" value={dispatchForm.target_ip} onChange={(e) => setDispatchForm((p) => ({ ...p, target_ip: e.target.value }))} required />
          <div className="grid grid-cols-2 gap-2">
            <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Target Port" value={dispatchForm.target_port} onChange={(e) => setDispatchForm((p) => ({ ...p, target_port: e.target.value }))} />
            <select className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" value={dispatchForm.protocol} onChange={(e) => setDispatchForm((p) => ({ ...p, protocol: e.target.value }))}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="any">any</option>
            </select>
          </div>
          <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Requested by" value={dispatchForm.requested_by} onChange={(e) => setDispatchForm((p) => ({ ...p, requested_by: e.target.value }))} />
          <input className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm" placeholder="Reason" value={dispatchForm.reason} onChange={(e) => setDispatchForm((p) => ({ ...p, reason: e.target.value }))} />
          <textarea className="w-full bg-black/50 border border-white/10 rounded px-3 py-2 text-sm font-mono" rows={3} placeholder="Payload overrides JSON" value={dispatchForm.payload_overrides_json} onChange={(e) => setDispatchForm((p) => ({ ...p, payload_overrides_json: e.target.value }))} />
          <button className="px-4 py-2 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-sm" type="submit">Dispatch</button>
        </form>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="card p-4 border border-white/10 bg-black/20">
          <h3 className="font-semibold text-orange-300 mb-3">Pending Approvals</h3>
          <div className="space-y-2 max-h-80 overflow-auto">
            {pendingActions.length === 0 ? <div className="text-sm text-gray-500">No pending actions.</div> : null}
            {pendingActions.map((action) => (
              <div key={action.id} className="p-3 rounded border border-white/10 bg-black/40 text-sm">
                <div className="font-mono text-xs text-gray-400">{action.id}</div>
                <div className="text-gray-200">{action.action_type} {'->'} {action.target_type}:{action.target_id}</div>
                <div className="text-gray-400 text-xs">{action.reason || '-'}</div>
                <div className="mt-2 flex gap-2">
                  <button className="px-3 py-1 rounded bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs" onClick={() => approveAction(action.id, true)}>Approve</button>
                  <button className="px-3 py-1 rounded bg-red-500/20 border border-red-500/30 text-red-300 text-xs" onClick={() => approveAction(action.id, false)}>Reject</button>
                  <button className="px-3 py-1 rounded bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs" onClick={() => loadAudit(action.id)}>Audit</button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-4 border border-white/10 bg-black/20">
          <h3 className="font-semibold text-cyan-300 mb-3">Recent Actions</h3>
          <div className="space-y-2 max-h-80 overflow-auto">
            {actions.map((action) => (
              <div key={action.id} className="p-3 rounded border border-white/10 bg-black/40 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-gray-400">{action.id}</span>
                  <span className="text-xs text-gray-300">{action.status}</span>
                </div>
                <div className="text-gray-200">{action.action_type} {'->'} {action.target_type}:{action.target_id}</div>
                <button className="mt-2 px-3 py-1 rounded bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs" onClick={() => loadAudit(action.id)}>View Audit</button>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card p-4 border border-white/10 bg-black/20">
        <h3 className="font-semibold text-cyan-300 mb-3">Audit Trail {selectedActionId ? `for ${selectedActionId}` : ''}</h3>
        <div className="space-y-2 max-h-80 overflow-auto">
          {auditLogs.length === 0 ? <div className="text-sm text-gray-500">Select an action to load audit entries.</div> : null}
          {auditLogs.map((item) => (
            <div key={item.id} className="p-3 rounded border border-white/10 bg-black/40 text-xs">
              <div className="flex justify-between gap-2 text-gray-300">
                <span>{item.event_type}</span>
                <span>{item.created_at}</span>
              </div>
              <div className="text-gray-500 mt-1">actor: {item.actor || 'n/a'}</div>
              <pre className="mt-2 whitespace-pre-wrap text-gray-400 font-mono">{JSON.stringify(item.details || {}, null, 2)}</pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
