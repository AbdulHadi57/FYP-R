import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ArrowDown, Shield, Brain, Crosshair, Users, Zap, Clock, CheckCircle2, AlertTriangle, Lock } from 'lucide-react';

const PipelineStage = ({ stage, index, isLast }) => {
  const statusColors = {
    active: 'border-emerald-500/60 bg-emerald-500/5 shadow-[0_0_20px_rgba(16,185,129,0.1)]',
    placeholder: 'border-gray-600/40 bg-gray-800/30',
  };

  const statusBadge = {
    active: { text: 'ACTIVE', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' },
    placeholder: { text: 'COMING SOON', color: 'bg-amber-500/20 text-amber-400 border-amber-500/40' },
  };

  const badge = statusBadge[stage.status];

  return (
    <>
      <div className={`relative rounded-xl border p-6 transition-all duration-500 hover:scale-[1.01] ${statusColors[stage.status]}`}>
        {/* Stage Number */}
        <div className="absolute -top-3 -left-3 w-8 h-8 rounded-full bg-gray-900 border border-cyan-500/40 flex items-center justify-center text-cyan-400 text-xs font-bold">
          {index}
        </div>

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          {/* Left: Icon + Info */}
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-lg ${stage.status === 'active' ? 'bg-emerald-500/10' : 'bg-gray-700/30'}`}>
              <stage.icon size={28} className={stage.status === 'active' ? 'text-emerald-400' : 'text-gray-500'} />
            </div>
            <div>
              <div className="flex items-center gap-3 mb-1">
                <h3 className="text-lg font-semibold text-gray-100">{stage.title}</h3>
                <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded-full border ${badge.color}`}>
                  {badge.text}
                </span>
              </div>
              <p className="text-sm text-gray-400 max-w-xl">{stage.description}</p>
            </div>
          </div>

          {/* Right: Meta */}
          <div className="flex flex-col gap-2 min-w-[200px]">
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-500 font-medium w-14">Input:</span>
              <span className="text-gray-300">{stage.input}</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-500 font-medium w-14">Output:</span>
              <span className="text-cyan-400">{stage.output}</span>
            </div>
            {stage.stats && (
              <div className="flex items-center gap-3 mt-1">
                {stage.stats.map((s, i) => (
                  <div key={i} className="text-center">
                    <div className="text-lg font-bold text-gray-100">{s.value}</div>
                    <div className="text-[10px] text-gray-500 uppercase">{s.label}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Active stage detail */}
        {stage.status === 'active' && stage.details && (
          <div className="mt-4 pt-4 border-t border-white/5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {stage.details.map((d, i) => (
                <div key={i} className="bg-black/20 rounded-lg p-3 text-center">
                  <div className="text-xs text-gray-500 mb-1">{d.label}</div>
                  <div className="text-sm font-semibold text-gray-200">{d.value}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Connector Arrow */}
      {!isLast && (
        <div className="flex justify-center py-2">
          <div className="flex flex-col items-center">
            <div className="w-px h-4 bg-gradient-to-b from-cyan-500/30 to-cyan-500/10"></div>
            <ArrowDown size={16} className="text-cyan-500/40" />
            <div className="w-px h-4 bg-gradient-to-b from-cyan-500/10 to-transparent"></div>
          </div>
        </div>
      )}
    </>
  );
};

export default function DetectionPipeline() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await axios.get('/api/stats');
        setStats(res.data);
      } catch (e) {
        // ignore
      }
    };
    fetchStats();
  }, []);

  const stages = [
    {
      title: 'Baseline Anomaly Detection',
      description: 'Unsupervised model trained on 1-week university network traffic to establish normal behavior baseline. Flags anomalous flows for secondary analysis, significantly reducing false positives.',
      icon: Shield,
      status: 'placeholder',
      input: 'Raw network flows',
      output: 'Normal / Anomalous flag',
      stats: null,
      details: null,
    },
    {
      title: 'Primary Threat Detection (JA4 + Flow Stats)',
      description: 'Ensemble ML model analyzing JA4+ fingerprints and CICFlowMeter/DoHlyzer flow statistics. Classifies traffic as malicious or benign with high confidence. Currently the active detection layer.',
      icon: Brain,
      status: 'active',
      input: 'JA4 hashes, flow statistics',
      output: 'Malicious / Benign verdict',
      stats: stats ? [
        { label: 'Total Flows', value: stats.total_flows?.toLocaleString() || '0' },
        { label: 'Malicious', value: stats.malicious_flows?.toLocaleString() || '0' },
        { label: 'Avg Severity', value: stats.avg_severity?.toFixed(2) || '0.00' },
      ] : null,
      details: stats ? [
        { label: 'Detection Rate', value: stats.total_flows > 0 ? ((stats.malicious_flows / stats.total_flows) * 100).toFixed(1) + '%' : '0%' },
        { label: 'Top Source', value: stats.top_source || 'N/A' },
        { label: 'Last Flow', value: stats.last_flow_timestamp ? new Date(stats.last_flow_timestamp).toLocaleTimeString() : 'N/A' },
        { label: 'Model', value: 'Ensemble + JA4' },
      ] : null,
    },
    {
      title: 'TTP Classification',
      description: 'Deep learning model analyzing the first 15-25 packets of flagged traffic along with JA4 hashes to predict MITRE ATT&CK tactics, techniques, and procedures (TTPs) and threat tags (phishing, C2, clickjacking, etc.).',
      icon: Crosshair,
      status: 'placeholder',
      input: 'First 15-25 packets, JA4 hashes, threat tags',
      output: 'MITRE TTPs + threat category tags',
      stats: null,
      details: null,
    },
    {
      title: 'APT Group Attribution',
      description: 'Maps predicted TTPs to known Advanced Persistent Threat (APT) groups. Identifies the 1-3 most likely threat actor groups behind the detected activity for threat intelligence reporting.',
      icon: Users,
      status: 'placeholder',
      input: 'MITRE TTPs from Layer 2',
      output: 'APT group association(s)',
      stats: null,
      details: null,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <Zap size={24} className="text-cyan-400" />
            Detection Pipeline
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            Multi-layer analysis pipeline — traffic flows through each stage sequentially
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
            <span className="text-gray-400">Active</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-amber-500"></div>
            <span className="text-gray-400">Coming Soon</span>
          </div>
        </div>
      </div>

      {/* Pipeline Flow */}
      <div className="space-y-0">
        {stages.map((stage, i) => (
          <PipelineStage key={i} stage={stage} index={i} isLast={i === stages.length - 1} />
        ))}
      </div>

      {/* Summary Card */}
      <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-6">
        <div className="flex items-start gap-4">
          <Lock size={20} className="text-cyan-400 mt-1 shrink-0" />
          <div>
            <h4 className="text-sm font-semibold text-cyan-400 mb-1">Privacy-Preserving Architecture</h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              All detection is performed on encrypted traffic metadata — JA4 fingerprints, flow statistics, and packet headers — without any SSL/TLS interception or payload decryption. 
              This eliminates the 6× performance overhead and privacy risks associated with decryption proxies while maintaining strong detection capability against APTs, C2 channels, and protocol abuse.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
