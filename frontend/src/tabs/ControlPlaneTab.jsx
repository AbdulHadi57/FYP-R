import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Shield, Server, Monitor, RefreshCw, CheckCircle2, XCircle, Clock, Trash2, ShieldOff, ShieldCheck, ChevronDown, ChevronRight, FileText, AlertTriangle, Wifi, WifiOff } from 'lucide-react';

const API = '';  // Relative, proxied by Vite

const StatusBadge = ({ status }) => {
  const colors = {
    online: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    offline: 'bg-red-500/20 text-red-400 border-red-500/40',
    pending: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    approved: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    rejected: 'bg-red-500/20 text-red-400 border-red-500/40',
    queued: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
    dispatched: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
    succeeded: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    failed: 'bg-red-500/20 text-red-400 border-red-500/40',
    pending_approval: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    cancelled: 'bg-gray-500/20 text-gray-400 border-gray-500/40',
    running: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
  };
  return (
    <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-full border ${colors[status] || 'bg-gray-500/20 text-gray-400 border-gray-500/40'}`}>
      {status?.replace('_', ' ') || 'unknown'}
    </span>
  );
};

const SectionHeader = ({ icon: Icon, title, count, children }) => (
  <div className="flex items-center justify-between mb-4">
    <h3 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
      <Icon size={20} className="text-cyan-400" />
      {title}
      {count !== undefined && <span className="text-sm text-gray-500 font-normal">({count})</span>}
    </h3>
    {children}
  </div>
);

// ─── Domain Controllers Section ─────────────────────────────────────────────
const DomainControllersSection = ({ dcs, onRefresh }) => {
  const [deleting, setDeleting] = useState(null);

  const handleApprove = async (dcId, approve) => {
    try {
      await axios.post(`${API}/api/control/dcs/${dcId}/approve?approved=${approve}&approved_by=soc_analyst`);
      onRefresh();
    } catch (e) {
      alert(`Failed: ${e.response?.data?.detail || e.message}`);
    }
  };

  const handleDelete = async (dcId) => {
    if (!confirm(`Remove DC ${dcId} and ALL its agents? This cannot be undone.`)) return;
    setDeleting(dcId);
    try {
      await axios.delete(`${API}/api/control/dcs/${dcId}`);
      onRefresh();
    } catch (e) {
      alert(`Failed: ${e.response?.data?.detail || e.message}`);
    } finally {
      setDeleting(null);
    }
  };

  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-5">
      <SectionHeader icon={Server} title="Domain Controllers" count={dcs.length}>
        <button onClick={onRefresh} className="text-xs text-gray-500 hover:text-cyan-400 transition-colors flex items-center gap-1">
          <RefreshCw size={12} /> Refresh
        </button>
      </SectionHeader>

      {dcs.length === 0 ? (
        <div className="text-center py-8 text-gray-600 text-sm">
          No domain controllers registered yet. Run <code className="text-cyan-400/60">run_dc_runner.py</code> on your DC to register.
        </div>
      ) : (
        <div className="space-y-3">
          {dcs.map(dc => (
            <div key={dc.id} className={`rounded-lg border p-4 transition-all ${dc.approval_status === 'pending' ? 'border-amber-500/30 bg-amber-500/5' : 'border-white/5 bg-black/20'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Server size={18} className={dc.status === 'online' ? 'text-emerald-400' : 'text-gray-600'} />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-200">{dc.hostname || dc.id}</span>
                      <StatusBadge status={dc.approval_status} />
                      <StatusBadge status={dc.status} />
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5 flex items-center gap-3">
                      <span>ID: {dc.id}</span>
                      {dc.domain_fqdn && <span>Domain: {dc.domain_fqdn}</span>}
                      {dc.fqdn && <span>FQDN: {dc.fqdn}</span>}
                      <span>Agents: {dc.agent_count || 0}</span>
                      {dc.last_seen && <span>Last: {new Date(dc.last_seen).toLocaleString()}</span>}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {dc.approval_status === 'pending' && (
                    <>
                      <button onClick={() => handleApprove(dc.id, true)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 transition-colors">
                        <CheckCircle2 size={12} /> Approve
                      </button>
                      <button onClick={() => handleApprove(dc.id, false)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition-colors">
                        <XCircle size={12} /> Reject
                      </button>
                    </>
                  )}
                  <button onClick={() => handleDelete(dc.id)} disabled={deleting === dc.id}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-400/70 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-50">
                    <Trash2 size={12} /> {deleting === dc.id ? 'Removing...' : 'Remove'}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── Agent Inventory Section ────────────────────────────────────────────────
const AgentInventorySection = ({ agents, dcs }) => {
  const [expandedDc, setExpandedDc] = useState({});

  // Group agents by dc_id
  const grouped = {};
  for (const dc of dcs) {
    grouped[dc.id] = { dc, agents: [] };
  }
  // Also add an "unassigned" group
  grouped['__unassigned__'] = { dc: null, agents: [] };

  for (const agent of agents) {
    const gKey = agent.dc_id && grouped[agent.dc_id] ? agent.dc_id : '__unassigned__';
    grouped[gKey].agents.push(agent);
  }

  const toggleDc = (dcId) => {
    setExpandedDc(prev => ({ ...prev, [dcId]: !prev[dcId] }));
  };

  const groups = Object.entries(grouped).filter(([_, v]) => v.agents.length > 0 || v.dc);

  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-5">
      <SectionHeader icon={Monitor} title="Agent Inventory" count={agents.length} />

      {agents.length === 0 ? (
        <div className="text-center py-8 text-gray-600 text-sm">
          No agents registered yet. Start <code className="text-cyan-400/60">run_agent.py</code> on endpoints to register.
        </div>
      ) : (
        <div className="space-y-3">
          {groups.map(([dcId, group]) => {
            const isExpanded = expandedDc[dcId] !== false; // Default expanded
            const dcLabel = group.dc ? `${group.dc.hostname || dcId} (${group.dc.domain_fqdn || 'no domain'})` : 'Unassigned Agents';
            return (
              <div key={dcId} className="rounded-lg border border-white/5 overflow-hidden">
                {/* DC group header */}
                <button onClick={() => toggleDc(dcId)}
                  className="w-full flex items-center justify-between p-3 bg-black/30 hover:bg-black/40 transition-colors text-left">
                  <div className="flex items-center gap-2">
                    {isExpanded ? <ChevronDown size={14} className="text-gray-500" /> : <ChevronRight size={14} className="text-gray-500" />}
                    <Server size={14} className="text-cyan-400/60" />
                    <span className="text-sm font-medium text-gray-300">{dcLabel}</span>
                    <span className="text-xs text-gray-600">({group.agents.length} agent{group.agents.length !== 1 ? 's' : ''})</span>
                  </div>
                  {group.dc && <StatusBadge status={group.dc.approval_status} />}
                </button>

                {/* Agent rows */}
                {isExpanded && group.agents.length > 0 && (
                  <div className="divide-y divide-white/5">
                    {group.agents.map(agent => (
                      <div key={agent.id} className="flex items-center justify-between px-4 py-2.5 bg-black/10 hover:bg-black/20 transition-colors">
                        <div className="flex items-center gap-3">
                          {agent.status === 'online'
                            ? <Wifi size={14} className="text-emerald-400" />
                            : <WifiOff size={14} className="text-gray-600" />}
                          <div>
                            <span className="text-sm text-gray-300">{agent.hostname || agent.id}</span>
                            <span className="text-xs text-gray-600 ml-2">{agent.id}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {agent.domain_fqdn && <span className="text-xs text-gray-500">{agent.domain_fqdn}</span>}
                          <StatusBadge status={agent.status} />
                          {agent.last_seen && <span className="text-[10px] text-gray-600">{new Date(agent.last_seen).toLocaleTimeString()}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ─── Active Response Section ────────────────────────────────────────────────
const ActiveResponseSection = ({ actions, agents, dcs, onRefresh }) => {
  const [isolateIp, setIsolateIp] = useState('');
  const [selectedDc, setSelectedDc] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  const approvedDcs = dcs.filter(d => d.approval_status === 'approved');

  const handleAction = async (actionType, targetIp) => {
    const dcId = selectedDc || (approvedDcs.length > 0 ? approvedDcs[0].id : '');
    if (!dcId) { alert('No approved DC available'); return; }
    if (!targetIp) { alert('Enter target IP'); return; }
    setActionLoading(true);
    try {
      await axios.post(`${API}/api/control/actions`, {
        target_type: 'dc',
        target_id: dcId,
        action_type: actionType,
        payload: { target_ip: targetIp },
        requested_by: 'soc_analyst',
        reason: `Manual ${actionType} from dashboard`,
        require_approval: false,
      });
      setIsolateIp('');
      onRefresh();
    } catch (e) {
      alert(`Failed: ${e.response?.data?.detail || e.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRollback = async (actionId) => {
    try {
      await axios.post(`${API}/api/control/actions/${actionId}/rollback`, {
        requested_by: 'soc_analyst',
        reason: 'Manual restore from dashboard',
      });
      onRefresh();
    } catch (e) {
      alert(`Failed: ${e.response?.data?.detail || e.message}`);
    }
  };

  // Filter to response-relevant actions
  const responseActions = actions.filter(a =>
    ['isolate_host', 'restore_host', 'block_ip', 'unblock_ip', 'quarantine_host', 'unquarantine_host', 'disable_ad_user', 'enable_ad_user'].includes(a.action_type)
  );

  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-5">
      <SectionHeader icon={ShieldOff} title="Active Response Controls" count={responseActions.length} />

      {/* Quick Action Bar */}
      <div className="flex items-center gap-3 mb-5 p-3 rounded-lg bg-black/30 border border-white/5">
        <input
          type="text"
          value={isolateIp}
          onChange={(e) => setIsolateIp(e.target.value)}
          placeholder="Target IP address"
          className="flex-1 bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 placeholder:text-gray-600 focus:border-cyan-500/50 focus:outline-none"
        />
        {approvedDcs.length > 1 && (
          <select value={selectedDc} onChange={(e) => setSelectedDc(e.target.value)}
            className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-cyan-500/50 focus:outline-none">
            <option value="">Auto (first DC)</option>
            {approvedDcs.map(dc => <option key={dc.id} value={dc.id}>{dc.hostname || dc.id}</option>)}
          </select>
        )}
        <button onClick={() => handleAction('isolate_host', isolateIp)} disabled={actionLoading || !isolateIp}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition-colors disabled:opacity-40">
          <ShieldOff size={14} /> Isolate
        </button>
        <button onClick={() => handleAction('restore_host', isolateIp)} disabled={actionLoading || !isolateIp}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 transition-colors disabled:opacity-40">
          <ShieldCheck size={14} /> Restore
        </button>
      </div>

      {/* Action History Table */}
      {responseActions.length === 0 ? (
        <div className="text-center py-6 text-gray-600 text-sm">No response actions recorded yet.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase border-b border-white/5">
                <th className="text-left py-2 px-3">Action</th>
                <th className="text-left py-2 px-3">Target</th>
                <th className="text-left py-2 px-3">Status</th>
                <th className="text-left py-2 px-3">Requested By</th>
                <th className="text-left py-2 px-3">Reason</th>
                <th className="text-left py-2 px-3">Time</th>
                <th className="text-left py-2 px-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {responseActions.map(action => (
                <tr key={action.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-2.5 px-3">
                    <span className={`text-xs font-medium ${action.action_type.includes('isolate') || action.action_type.includes('block') || action.action_type.includes('disable') ? 'text-red-400' : 'text-emerald-400'}`}>
                      {action.action_type.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 font-mono text-xs">{action.target_id}</td>
                  <td className="py-2.5 px-3"><StatusBadge status={action.status} /></td>
                  <td className="py-2.5 px-3 text-gray-400 text-xs">{action.requested_by || 'system'}</td>
                  <td className="py-2.5 px-3 text-gray-500 text-xs max-w-[200px] truncate">{action.reason || '-'}</td>
                  <td className="py-2.5 px-3 text-gray-500 text-xs whitespace-nowrap">{action.created_at ? new Date(action.created_at).toLocaleString() : '-'}</td>
                  <td className="py-2.5 px-3">
                    {action.status === 'succeeded' && !action.rollback_of_action_id && (
                      <button onClick={() => handleRollback(action.id)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1">
                        <RefreshCw size={10} /> Rollback
                      </button>
                    )}
                    {action.rollback_of_action_id && (
                      <span className="text-xs text-gray-600 italic">rollback of {action.rollback_of_action_id.slice(0, 12)}…</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// ─── Main Control Plane Tab ─────────────────────────────────────────────────
export default function ControlPlaneTab() {
  const [dcs, setDcs] = useState([]);
  const [agents, setAgents] = useState([]);
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [dcRes, agentRes, actionsRes] = await Promise.all([
        axios.get(`${API}/api/control/dcs`).catch(() => ({ data: [] })),
        axios.get(`${API}/api/control/agents`).catch(() => ({ data: [] })),
        axios.get(`${API}/api/control/actions?limit=100`).catch(() => ({ data: [] })),
      ]);
      setDcs(dcRes.data);
      setAgents(agentRes.data);
      setActions(actionsRes.data);
    } catch (e) {}
    setLoading(false);
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(fetchAll, 10000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
          <Shield size={24} className="text-cyan-400" />
          Control Plane
        </h2>
        <p className="text-sm text-gray-500 mt-1">
          Manage domain controllers, agents, and active response
        </p>
      </div>

      {/* Pending DC Warning */}
      {dcs.some(d => d.approval_status === 'pending') && (
        <div className="flex items-center gap-3 p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
          <AlertTriangle size={18} className="text-amber-400 shrink-0" />
          <span className="text-sm text-amber-300">
            {dcs.filter(d => d.approval_status === 'pending').length} domain controller(s) pending approval. Agents cannot register until a DC is approved.
          </span>
        </div>
      )}

      <DomainControllersSection dcs={dcs} onRefresh={fetchAll} />
      <AgentInventorySection agents={agents} dcs={dcs} />
      <ActiveResponseSection actions={actions} agents={agents} dcs={dcs} onRefresh={fetchAll} />
    </div>
  );
}
