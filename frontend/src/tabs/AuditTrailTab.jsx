import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { FileText, RefreshCw, Filter, ChevronDown, Clock, Shield, ShieldOff, ShieldCheck, User, Server, Trash2, CheckCircle2, XCircle, Undo2 } from 'lucide-react';

const API = '';

const eventConfig = {
  created:             { color: 'text-blue-400',    bg: 'bg-blue-500/10',    icon: Shield,       label: 'Action Created' },
  approved:            { color: 'text-emerald-400', bg: 'bg-emerald-500/10', icon: CheckCircle2, label: 'Approved' },
  rejected:            { color: 'text-red-400',     bg: 'bg-red-500/10',     icon: XCircle,      label: 'Rejected' },
  dispatched:          { color: 'text-cyan-400',    bg: 'bg-cyan-500/10',    icon: Server,       label: 'Dispatched' },
  status_update:       { color: 'text-amber-400',   bg: 'bg-amber-500/10',   icon: RefreshCw,    label: 'Status Update' },
  rollback_requested:  { color: 'text-purple-400',  bg: 'bg-purple-500/10',  icon: Undo2,        label: 'Rollback Requested' },
  dc_approved:         { color: 'text-emerald-400', bg: 'bg-emerald-500/10', icon: CheckCircle2, label: 'DC Approved' },
  dc_rejected:         { color: 'text-red-400',     bg: 'bg-red-500/10',     icon: XCircle,      label: 'DC Rejected' },
  dc_deleted:          { color: 'text-red-400',     bg: 'bg-red-500/10',     icon: Trash2,       label: 'DC Deleted' },
  templated_dispatch:  { color: 'text-cyan-400',    bg: 'bg-cyan-500/10',    icon: ShieldOff,    label: 'Response Dispatched' },
};

const actionTypeLabels = {
  isolate_host: 'Isolate Host',
  restore_host: 'Restore Host',
  block_ip: 'Block IP',
  unblock_ip: 'Unblock IP',
  quarantine_host: 'Quarantine',
  unquarantine_host: 'Unquarantine',
  disable_ad_user: 'Disable AD User',
  enable_ad_user: 'Enable AD User',
  disable_ad_computer: 'Disable AD PC',
  enable_ad_computer: 'Enable AD PC',
  ping: 'Ping',
  noop: 'No-Op',
  log_message: 'Log Message',
};

export default function AuditTrailTab() {
  const [trail, setTrail] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchTrail = useCallback(async () => {
    setLoading(true);
    try {
      let url = `${API}/api/control/audit-trail?limit=200`;
      if (filterType !== 'all') {
        url += `&action_type=${filterType}`;
      }
      const res = await axios.get(url);
      setTrail(res.data);
    } catch (e) {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [filterType]);

  useEffect(() => { fetchTrail(); }, [fetchTrail]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchTrail, 10000);
    return () => clearInterval(interval);
  }, [fetchTrail, autoRefresh]);

  const formatTime = (ts) => {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleString();
  };

  const getConfig = (eventType) => {
    return eventConfig[eventType] || { color: 'text-gray-400', bg: 'bg-gray-500/10', icon: Clock, label: eventType?.replace(/_/g, ' ') || 'Unknown' };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <FileText size={24} className="text-cyan-400" />
            Audit Trail
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            Chronological log of all control-plane actions, responses, and administrative events
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              autoRefresh
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-gray-500/10 text-gray-400 border-gray-500/30'
            }`}
          >
            <div className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`}></div>
            {autoRefresh ? 'Live' : 'Paused'}
          </button>
          <button onClick={fetchTrail} disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 text-gray-400 border border-white/10 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-4 p-3 rounded-xl border border-white/10 bg-black/20">
        <Filter size={14} className="text-gray-500" />
        <span className="text-xs text-gray-500 uppercase tracking-wider">Filter by action:</span>
        <div className="relative">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="appearance-none bg-black/30 border border-white/10 rounded-lg pl-3 pr-8 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-cyan-500/50 cursor-pointer"
          >
            <option value="all">All Actions</option>
            <option value="isolate_host">Isolate Host</option>
            <option value="restore_host">Restore Host</option>
            <option value="block_ip">Block IP</option>
            <option value="unblock_ip">Unblock IP</option>
            <option value="quarantine_host">Quarantine</option>
            <option value="disable_ad_user">Disable AD User</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
        </div>
        <span className="text-xs text-gray-600 ml-auto">{trail.length} entries</span>
      </div>

      {/* Timeline */}
      <div className="rounded-xl border border-white/10 bg-black/20 p-5">
        {trail.length === 0 ? (
          <div className="text-center py-16 text-gray-600">
            <FileText size={40} className="mx-auto mb-4 opacity-30" />
            <p className="text-sm">No audit entries yet.</p>
            <p className="text-xs mt-1 text-gray-700">Actions like isolate, restore, DC approval, and agent registration will appear here.</p>
          </div>
        ) : (
          <div className="space-y-1">
            {/* Table Header */}
            <div className="flex items-center gap-3 py-2 px-3 text-[10px] text-gray-600 uppercase tracking-widest border-b border-white/5 mb-2">
              <div className="w-[170px] shrink-0">Timestamp</div>
              <div className="w-[180px] shrink-0">Event</div>
              <div className="w-[110px] shrink-0">Actor</div>
              <div className="w-[130px] shrink-0">Target</div>
              <div className="w-[120px] shrink-0">Action Type</div>
              <div className="w-[90px] shrink-0">Job Status</div>
              <div className="flex-1">Details</div>
            </div>

            {/* Rows */}
            <div className="max-h-[600px] overflow-y-auto space-y-0.5 pr-1 scrollbar-thin">
              {trail.map((entry, i) => {
                const cfg = getConfig(entry.event_type);
                const EventIcon = cfg.icon;
                return (
                  <div key={entry.id || i}
                    className="flex items-center gap-3 py-2.5 px-3 rounded-lg hover:bg-white/[0.03] transition-colors group"
                  >
                    {/* Timestamp */}
                    <div className="text-xs text-gray-600 w-[170px] shrink-0 font-mono">
                      {formatTime(entry.created_at)}
                    </div>

                    {/* Event Type */}
                    <div className="w-[180px] shrink-0 flex items-center gap-2">
                      <div className={`p-1 rounded ${cfg.bg}`}>
                        <EventIcon size={12} className={cfg.color} />
                      </div>
                      <span className={`text-xs font-medium ${cfg.color}`}>
                        {cfg.label}
                      </span>
                    </div>

                    {/* Actor */}
                    <div className="w-[110px] shrink-0 flex items-center gap-1.5">
                      <User size={10} className="text-gray-600" />
                      <span className="text-xs text-gray-400 truncate">{entry.actor || 'system'}</span>
                    </div>

                    {/* Target */}
                    <div className="w-[130px] shrink-0">
                      <span className="text-xs text-gray-300 font-mono truncate block">
                        {entry.target_info || entry.job_target_id || '-'}
                      </span>
                    </div>

                    {/* Action Type */}
                    <div className="w-[120px] shrink-0">
                      {entry.job_action_type ? (
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                          entry.job_action_type.includes('isolate') || entry.job_action_type.includes('block') || entry.job_action_type.includes('disable')
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : entry.job_action_type.includes('restore') || entry.job_action_type.includes('unblock') || entry.job_action_type.includes('enable')
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-gray-500/10 text-gray-400 border-gray-500/30'
                        }`}>
                          {actionTypeLabels[entry.job_action_type] || entry.job_action_type.replace(/_/g, ' ')}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-600">-</span>
                      )}
                    </div>

                    {/* Job Status */}
                    <div className="w-[90px] shrink-0">
                      {entry.job_status ? (
                        <span className={`text-[10px] font-bold uppercase ${
                          entry.job_status === 'succeeded' ? 'text-emerald-400' :
                          entry.job_status === 'failed' ? 'text-red-400' :
                          entry.job_status === 'dispatched' ? 'text-cyan-400' :
                          entry.job_status === 'queued' ? 'text-blue-400' :
                          'text-gray-500'
                        }`}>
                          {entry.job_status}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-600">-</span>
                      )}
                    </div>

                    {/* Details */}
                    <div className="flex-1 text-xs text-gray-600 truncate group-hover:text-gray-500 transition-colors">
                      {(() => {
                        const d = entry.details || {};
                        const parts = [];
                        if (d.action_type) parts.push(`type: ${d.action_type}`);
                        if (d.target_type) parts.push(`target: ${d.target_type}`);
                        if (d.status) parts.push(`status: ${d.status}`);
                        if (d.note) parts.push(`note: "${d.note}"`);
                        if (d.template_name) parts.push(`template: ${d.template_name}`);
                        if (d.origin_agent_id) parts.push(`agent: ${d.origin_agent_id}`);
                        if (d.dc_id) parts.push(`dc: ${d.dc_id}`);
                        if (d.rollback_of) parts.push(`rollback of: ${d.rollback_of.slice(0, 12)}…`);
                        if (d.cascaded_agents_removed?.length) parts.push(`removed ${d.cascaded_agents_removed.length} agent(s)`);
                        return parts.length > 0 ? parts.join(' · ') : JSON.stringify(d).slice(0, 60);
                      })()}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
