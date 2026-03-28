
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
    LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    BarChart, Bar, PieChart, Pie, Cell, Legend, RadialBarChart, RadialBar, PolarAngleAxis
} from 'recharts';
import { Shield, Activity, Clock, Fingerprint, AlertTriangle } from 'lucide-react';
import KPIWidget from '../components/KPIWidget';

export default function ThreatOverview() {
    const [stats, setStats] = useState(null);
    const [timeline, setTimeline] = useState([]);
    const [modules, setModules] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [statsRes, timelineRes, modulesRes] = await Promise.all([
                    axios.get('/api/stats'),
                    axios.get('/api/timeline'),
                    axios.get('/api/modules?limit=2000')
                ]);
                setStats(statsRes.data);
                setTimeline(timelineRes.data);
                setModules(modulesRes.data);
            } catch (error) {
                console.error("Error fetching data:", error);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const COLORS = ['#ff4b4b', '#00cc96', '#00e0ff', '#ffbb28'];

    // Avg duration is not in stats, using placeholder or calculating from modules if possible
    // Actually, we can assume modules.apt_stats has durations.
    const avgDuration = modules?.apt_stats?.length
        ? (modules.apt_stats.reduce((acc, curr) => acc + curr.duration, 0) / modules.apt_stats.length).toFixed(2) + "s"
        : "0s";

    // Calc resolution rate for gauge
    const open = modules?.threat_status_distribution?.open || 0;
    const resolved = modules?.threat_status_distribution?.resolved || 0;
    const total = open + resolved;
    const resolutionRate = total > 0 ? Math.round((resolved / total) * 100) : 0;

    // Calc active threat rate
    const totalFlows = stats?.total_flows || 1;
    const maliciousFlows = stats?.malicious_flows || 0;
    const activeThreatRate = ((maliciousFlows / totalFlows) * 100).toFixed(1) + "% Rate";

    const gaugeData = [
        {
            name: 'Rate',
            value: resolutionRate,
            fill: '#10b981'
        }
    ];

    const pieData = [
        { name: 'Malicious', value: stats?.malicious_flows || 0 },
        { name: 'Benign', value: (stats?.total_flows || 0) - (stats?.malicious_flows || 0) }
    ];

    return (
        <div className="space-y-6">
            {/* Top Row: KPIs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6">
                <KPIWidget
                    title="Total Connections"
                    value={stats?.total_flows?.toLocaleString() || "0"}
                    subtext="Total captured flows"
                    icon={Activity}
                    color="blue"
                />
                <KPIWidget
                    title="Threats Identified"
                    value={stats?.malicious_flows?.toLocaleString() || "0"}
                    subtext={activeThreatRate}
                    icon={AlertTriangle}
                    color="red"
                />
                <KPIWidget
                    title="Avg Flow Duration"
                    value={avgDuration}
                    subtext="Seconds per flow"
                    icon={Clock}
                    color="green"
                />
                <KPIWidget
                    title="Unique JA4"
                    value={modules?.ja4_diversity || "0"}
                    subtext="Client Fingerprints"
                    icon={Fingerprint}
                    color="blue"
                />
            </div>

            {/* Middle Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Donut Chart */}
                <div className="card h-80">
                    <h3 className="text-lg font-semibold text-white mb-4">Traffic Composition</h3>
                    <div className="flex-1 min-h-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <defs>
                                    <filter id="neonGlow" height="300%" width="300%" x="-75%" y="-75%">
                                        <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                                        <feMerge>
                                            <feMergeNode in="coloredBlur" />
                                            <feMergeNode in="SourceGraphic" />
                                        </feMerge>
                                    </filter>
                                </defs>
                                {/* Hairline Track */}
                                <Pie
                                    data={[{ value: 1 }]}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={79}
                                    outerRadius={80}
                                    dataKey="value"
                                    stroke="none"
                                    fill="rgba(255,255,255,0.1)"
                                    isAnimationActive={false}
                                />
                                {/* Cyber Data Ring */}
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={75}
                                    outerRadius={85}
                                    paddingAngle={5}
                                    cornerRadius={2}
                                    dataKey="value"
                                    stroke="none"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell
                                            key={"cell-" + index}
                                            fill={index === 0 ? '#ff0055' : '#14d9d1'}
                                            className="filter"
                                            style={{ filter: "drop-shadow(0 0 2px " + (index === 0 ? '#ff0055' : '#14d9d1') + ")" }}
                                        />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={{ backgroundColor: 'rgba(0,0,0,0.9)', border: '1px solid #00ffff', color: '#00ffff', borderRadius: '0px', boxShadow: '0 0 10px #00ffff' }} itemStyle={{ color: '#00ffff', fontFamily: 'monospace' }} />
                                <text x="50%" y="50%" dy={8} textAnchor="middle" className="fill-white text-3xl font-mono tracking-widest" style={{ filter: 'drop-shadow(0 0 3px white)' }}>
                                    {stats?.malicious_flows || 0}
                                </text>
                                <text x="50%" y="65%" dy={5} textAnchor="middle" className="fill-cyan-400 text-[10px] uppercase tracking-[0.2em] font-mono">
                                    THREATS
                                </text>
                                <Legend verticalAlign="bottom" height={36} iconType="rect" />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Timeline Line Chart */}
                <div className="card h-80">
                    <h3 className="text-lg font-semibold text-white mb-4">Traffic Volume & Spikes</h3>
                    <div className="flex-1 min-h-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={timeline}>
                                <defs>
                                    <linearGradient id="colorFlows" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#00e0ff" stopOpacity={0.8} />
                                        <stop offset="95%" stopColor="#00e0ff" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                                <XAxis
                                    dataKey="bucket"
                                    stroke="#666"
                                    tick={{ fontSize: 12 }}
                                    tickFormatter={(val) => {
                                        if (!val) return '';
                                        const parts = val.split('T');
                                        return parts.length > 1 ? parts[1] : val.split(' ')[1] || val;
                                    }}
                                />
                                <YAxis stroke="#666" />
                                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff' }} />
                                <Area type="monotone" dataKey="flow_count" stroke="#00e0ff" fillOpacity={1} fill="url(#colorFlows)" />
                                <Area type="monotone" dataKey="malicious_count" stroke="#ff4b4b" fill="none" strokeWidth={2} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* Shared Definitions for Gradients and Filters */}
            <div style={{ height: 0, width: 0, overflow: 'hidden' }}>
                <svg>
                    <defs>
                        <linearGradient id="barGradient" x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor="#ef4444" stopOpacity={0.8} />
                            <stop offset="100%" stopColor="#f43f5e" stopOpacity={1} />
                        </linearGradient>
                        <linearGradient id="gaugeGradient" x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor="#10b981" />
                            <stop offset="50%" stopColor="#06b6d4" />
                            <stop offset="100%" stopColor="#3b82f6" />
                        </linearGradient>
                        <linearGradient id="pieOpen" x1="0" y1="0" x2="1" y2="1">
                            <stop offset="0%" stopColor="#ef4444" />
                            <stop offset="100%" stopColor="#b91c1c" />
                        </linearGradient>
                        <linearGradient id="pieResolved" x1="0" y1="0" x2="1" y2="1">
                            <stop offset="0%" stopColor="#10b981" />
                            <stop offset="100%" stopColor="#059669" />
                        </linearGradient>
                        <filter id="neonGlowIntense" height="300%" width="300%" x="-75%" y="-75%">
                            <feGaussianBlur stdDeviation="4" result="coloredBlur" />
                            <feMerge>
                                <feMergeNode in="coloredBlur" />
                                <feMergeNode in="SourceGraphic" />
                            </feMerge>
                        </filter>
                    </defs>
                </svg>
            </div>



            {/* New Analytics Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Module Activity Chart */}
                <div className="card h-80 relative">
                    <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
                        <span className="w-1 h-6 bg-purple-500 rounded-full"></span>
                        Module Activity
                    </h3>
                    <div className="flex-1 min-h-0 mt-4">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={modules?.module_activity ? Object.entries(modules.module_activity).map(([k, v]) => ({ name: k.toUpperCase(), value: v })) : []}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                                <XAxis dataKey="name" stroke="#666" tick={{ fill: '#e2e8f0', fontSize: 11, fontWeight: 'bold' }} />
                                <YAxis stroke="#666" width={40} tick={{ fontSize: 10 }} />
                                <Tooltip
                                    cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                                    content={({ active, payload, label }) => {
                                        if (active && payload && payload.length) {
                                            return (
                                                <div className="bg-black/90 border border-purple-500/30 p-2 rounded backdrop-blur-md shadow-[0_0_10px_rgba(168,85,247,0.2)]">
                                                    <p className="text-purple-400 text-[10px] font-bold tracking-widest uppercase mb-1">{label}</p>
                                                    <p className="text-white text-lg font-bold font-mono">
                                                        {payload[0].value} <span className="text-xs text-gray-500 font-sans font-normal">detections</span>
                                                    </p>
                                                </div>
                                            );
                                        }
                                        return null;
                                    }}
                                />
                                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                                    {
                                        (modules?.module_activity ? Object.entries(modules.module_activity) : []).map((entry, index) => (
                                            <Cell
                                                key={"cell-" + index}
                                                fill={['#a855f7', '#ec4899', '#ef4444'][index % 3]}
                                                style={{ filter: 'drop-shadow(0 0 4px rgba(168,85,247,0.4))' }}
                                            />
                                        ))
                                    }
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Open vs Resolved Chart (NOW GAUGE) */}
                <div className="card h-80 relative">
                    <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
                        <span className="w-1 h-6 bg-emerald-500 rounded-full"></span>
                        Response Efficiency
                    </h3>

                    <div className="flex flex-row items-center h-full pb-8">
                        {/* Legend Side */}
                        <div className="flex flex-col gap-4 pl-4 min-w-[120px]">
                            <div className="flex items-center gap-3">
                                <span className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_5px_rgba(239,68,68,0.8)]"></span>
                                <span className="text-xs text-gray-400 uppercase tracking-widest">Open</span>
                                <span className="text-sm font-bold text-red-400 font-mono drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]">{open}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.8)]"></span>
                                <span className="text-xs text-gray-400 uppercase tracking-widest">Resolved</span>
                                <span className="text-sm font-bold text-emerald-400 font-mono drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]">{resolved}</span>
                            </div>
                        </div>

                        {/* Chart Side (Radial Bar Gauge) */}
                        <div className="flex-1 h-full relative flex items-center justify-center">
                            <ResponsiveContainer width="100%" height="100%">
                                <RadialBarChart
                                    cx="50%"
                                    cy="60%" // Shift down slightly for semi-circle
                                    innerRadius="70%"
                                    outerRadius="100%"
                                    barSize={20}
                                    data={gaugeData}
                                    startAngle={180}
                                    endAngle={0}
                                >
                                    <PolarAngleAxis
                                        type="number"
                                        domain={[0, 100]}
                                        angleAxisId={0}
                                        tick={false}
                                    />
                                    <RadialBar
                                        background={{ fill: 'rgba(221, 35, 51, 0.8)' }}
                                        clockWise
                                        dataKey="value"
                                        cornerRadius={10}
                                        fill="url(#gaugeGradient)"
                                    >
                                        <Cell style={{ filter: 'drop-shadow(0 0 6px rgba(16,185,129,0.5))' }} />
                                    </RadialBar>
                                </RadialBarChart>
                            </ResponsiveContainer>
                            {/* Center Statistic */}
                            <div className="absolute top-[55%] left-1/2 -translate-x-1/2 -translate-y-1/2 text-center pointer-events-none">
                                <span className="block text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400 tracking-widest font-mono" style={{ filter: "drop-shadow(0 0 10px rgba(16,185,129,0.5))" }}>
                                    {resolutionRate}%
                                </span>
                                <span className="text-[10px] text-gray-400 font-mono tracking-widest uppercase">Resolution</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            {/* Bottom Row: Top 10 Attackers */}
            <div className="card h-96 relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-4 opacity-50">
                    <Fingerprint size={100} className="text-red-500/10" />
                </div>
                <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
                    <span className="w-1 h-6 bg-red-500 rounded-full"></span>
                    <span>Top Attacking IPs</span>
                </h3>
                <p className="text-xs text-gray-500 mb-4 font-mono">HIGHEST VOLUME OFFENDERS</p>

                <div className="flex-1 min-h-0 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart layout="vertical" data={stats?.top_attackers || []} barSize={16}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" horizontal={false} />
                            <XAxis type="number" stroke="#666" tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                            <YAxis
                                dataKey="ip"
                                type="category"
                                stroke="#999"
                                width={130}
                                tick={{ fontSize: 11, fill: '#ccc', fontFamily: 'monospace' }}
                            />
                            <Tooltip
                                cursor={{ fill: 'rgba(239, 68, 68, 0.05)' }}
                                content={({ active, payload }) => {
                                    if (active && payload && payload.length) {
                                        return (
                                            <div className="bg-black/90 border border-red-500/50 p-3 rounded shadow-[0_0_15px_rgba(239,68,68,0.3)] backdrop-blur-md">
                                                <p className="text-red-400 text-xs font-bold font-mono mb-1">TARGET IDENTIFIED</p>
                                                <p className="text-white text-sm font-bold">{payload[0].payload.ip}</p>
                                                <div className="flex items-center gap-2 mt-2">
                                                    <span className="text-gray-400 text-xs">Volume:</span>
                                                    <span className="text-red-400 text-sm font-bold font-mono">{payload[0].value}</span>
                                                </div>
                                            </div>
                                        );
                                    }
                                    return null;
                                }}
                            />
                            <Bar dataKey="count" fill="url(#barGradient)" radius={[0, 4, 4, 0]}>
                                {
                                    (stats?.top_attackers || []).map((entry, index) => (
                                        <Cell key={"cell-" + index} style={{ filter: 'drop-shadow(0 0 2px rgba(239,68,68,0.5))' }} />
                                    ))
                                }
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
                <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-red-500/20 to-transparent"></div>
            </div>
        </div>
    );
}
