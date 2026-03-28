import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import KPIWidget from '../../components/KPIWidget';
import { Fingerprint, Hash, Layers, Server, Globe, Key, Clock, Network, Wifi, ShieldCheck, Info, Activity } from 'lucide-react';


const TABS = [
    {
        id: 'ja4', label: 'JA4', title: 'TLS Client', desc: 'TLS Client Fingerprinting', dataKey: 'top_ja4', icon: Fingerprint, color: '#00e0ff',
        format: 'a_b_c',
        components: [
            { id: 'a', label: 'TLS Header', desc: 'Proto, Version, SNI, Cnt, ALPN' },
            { id: 'b', label: 'Cipher Hash', desc: 'Hash of Cipher Suites' },
            { id: 'c', label: 'Ext Hash', desc: 'Hash of Extensions' }
        ]
    },
    {
        id: 'ja4s', label: 'JA4S', title: 'TLS Server', desc: 'TLS Server Response / Session Fingerprinting', dataKey: 'top_ja4s', icon: Server, color: '#ffbb28',
        format: 'a_b_c',
        components: [
            { id: 'a', label: 'TLS Header', desc: 'Proto, Version, Cnt, ALPN' },
            { id: 'b', label: 'Cipher Hex', desc: 'Selected Cipher Suite' },
            { id: 'c', label: 'Ext Hash', desc: 'Hash of Extensions' }
        ]
    },
    {
        id: 'ja4h', label: 'JA4H', title: 'HTTP Client', desc: 'HTTP Client Fingerprinting', dataKey: 'top_ja4h', icon: Globe, color: '#00cc96',
        format: 'a_b_c_d',
        components: [
            { id: 'a', label: 'HTTP Header', desc: 'Method, Ver, Cookie, Ref, Lang' },
            { id: 'b', label: 'Header Hash', desc: 'Hash of Headers' },
            { id: 'c', label: 'Name Hash', desc: 'Cookie Name Hash' },
            { id: 'd', label: 'Value Hash', desc: 'Cookie Value Hash' }
        ]
    },
    {
        id: 'ja4x', label: 'JA4X', title: 'X.509 Cert', desc: 'X509 TLS Certificate Fingerprinting', dataKey: 'top_ja4x', icon: ShieldCheck, color: '#ab61ff',
        format: 'a_b_c',
        components: [
            { id: 'a', label: 'Issuer Hash', desc: 'Hash of Issuer OIDs' },
            { id: 'b', label: 'Subject Hash', desc: 'Hash of Subject OIDs' },
            { id: 'c', label: 'Ext Hash', desc: 'Hash of Extension OIDs' }
        ]
    },
    {
        id: 'ja4ssh', label: 'JA4SSH', title: 'SSH', desc: 'SSH Traffic Fingerprinting', dataKey: 'top_ja4ssh', icon: Key, color: '#ff4b4b',
        format: 'a_b_c',
        components: [
            { id: 'a', label: 'Payload Dist', desc: 'Mode of Payload Sizes' },
            { id: 'b', label: 'Packet Cnts', desc: 'Client/Server Packet Counts' },
            { id: 'c', label: 'ACK Cnts', desc: 'Client/Server ACK Counts' }
        ]
    },
    {
        id: 'ja4t', label: 'JA4T', title: 'TCP Client', desc: 'TCP Client Fingerprinting', dataKey: 'top_ja4t', icon: Network, color: '#29b6f6',
        format: 'a_b_c_d',
        components: [
            { id: 'a', label: 'Window', desc: 'TCP Window Size' },
            { id: 'b', label: 'Options', desc: 'TCP Options List' },
            { id: 'c', label: 'MSS', desc: 'Max Segment Size' },
            { id: 'd', label: 'Scale', desc: 'Window Scale' }
        ]
    },
    {
        id: 'ja4ts', label: 'JA4TS', title: 'TCP Server', desc: 'TCP Server Response Fingerprinting', dataKey: 'top_ja4ts', icon: Server, color: '#ffa726',
        format: 'a_b_c_d',
        components: [
            { id: 'a', label: 'Window', desc: 'TCP Window Size' },
            { id: 'b', label: 'Options', desc: 'TCP Options List' },
            { id: 'c', label: 'MSS', desc: 'Max Segment Size' },
            { id: 'd', label: 'Scale', desc: 'Window Scale' }
        ]
    },
    {
        id: 'ja4l', label: 'JA4L', title: 'Latency', desc: 'Client/Server Latency Measurement', dataKey: 'top_ja4l', icon: Clock, color: '#ef5350',
        format: 'a_b_c',
        components: [
            { id: 'a', label: 'Latency', desc: 'Connection Latency (us)' },
            { id: 'b', label: 'TTL', desc: 'Time To Live' },
            { id: 'c', label: 'App Lat', desc: 'Application Latency' }
        ]
    },
    {
        id: 'ja4d', label: 'JA4D', title: 'DHCP', desc: 'DHCP Fingerprinting', dataKey: 'top_ja4d', icon: Wifi, color: '#66bb6a',
        format: 'a_b_c',
        components: [
            { id: 'a', label: 'DHCP Head', desc: 'Type, Size, IP, FQDN' },
            { id: 'b', label: 'Options', desc: 'Option Codes' },
            { id: 'c', label: 'Req List', desc: 'Request List' }
        ]
    },
];

// Update props to accept onNavigateFlow (though we might use local now)
import FlowDetailPanel from '../../components/FlowDetailPanel';

export default function JA4Module({ onNavigateFlow }) {
    const [data, setData] = useState(null);
    const [activeTabId, setActiveTabId] = useState('ja4');

    // Local Inspection State
    const [selectedFlow, setSelectedFlow] = useState(null);
    const [detailLoading, setDetailLoading] = useState(false);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await axios.get('/api/modules?limit=2000');
                setData(res.data);
            } catch (error) {
                console.error("Error fetching module data:", error);
            }
        };
        fetchData();
        const interval = setInterval(fetchData, 5000); // Auto-refresh every 5s
        return () => clearInterval(interval);
    }, []);

    const handleInspect = async (flowId) => {
        setDetailLoading(true);
        setSelectedFlow(null); // Clear previous to show loading
        try {
            const res = await axios.get(`/api/flows/${flowId}`);
            setSelectedFlow(res.data);
        } catch (error) {
            console.error("Error fetching flow details:", error);
        } finally {
            setDetailLoading(false);
        }
    };

    if (!data) return <div className="text-white">Loading JA4 Analysis...</div>;

    const activeTab = TABS.find(t => t.id === activeTabId) || TABS[0];
    const chartData = data[activeTab.dataKey] || [];
    const diversityCount = activeTabId === 'ja4' ? data.ja4_diversity : (activeTabId === 'ja4s' ? data.ja4s_diversity : chartData.length);
    const maliciousFlows = data.ja4_malicious_flows || [];

    return (
        <div className="space-y-6 pb-12 relative">
            {/* JA4 Detection Module - Pinned at Top */}
            <div className="card flex flex-col md:flex-row gap-6 p-6 min-h-[450px]">
                {/* Visual Stats Column */}
                <div className="w-full md:w-1/3 flex flex-col gap-4 border-r border-gray-800 pr-4">
                    <div>
                        <h3 className="text-xl font-bold text-white mb-1 flex items-center gap-2">
                            <ShieldCheck className="text-primary" size={24} />
                            JA4 Detection Module
                        </h3>
                        <p className="text-gray-400 text-sm mb-4">Machine Learning Verdict based on behavioral fingerprinting.</p>

                        <div className="flex items-center gap-8 mb-4">
                            <div className="text-center">
                                <div className="text-3xl font-mono font-bold text-danger">{data.ja4_malicious_count || 0}</div>
                                <div className="text-xs text-gray-400 uppercase tracking-widest">Malicious</div>
                            </div>
                            <div className="text-center">
                                <div className="text-3xl font-mono font-bold text-success">{data.ja4_benign_count || 0}</div>
                                <div className="text-xs text-gray-400 uppercase tracking-widest">Benign</div>
                            </div>
                        </div>
                    </div>

                    <div className="flex-1 min-h-[150px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                {/* Hairline Track */}
                                <Pie
                                    data={[{ value: 1 }]}
                                    innerRadius={79}
                                    outerRadius={80}
                                    dataKey="value"
                                    stroke="none"
                                    fill="rgba(255,255,255,0.1)"
                                    isAnimationActive={false}
                                    legendType="none"
                                />
                                {/* Cyber Data Ring */}
                                <Pie
                                    data={[
                                        { name: 'Malicious', value: data.ja4_malicious_count || 0 },
                                        { name: 'Benign', value: data.ja4_benign_count || 0 }
                                    ]}
                                    innerRadius={75}
                                    outerRadius={85}
                                    paddingAngle={5}
                                    cornerRadius={2}
                                    dataKey="value"
                                    stroke="none"
                                >
                                    <Cell fill="#ff0055" style={{ filter: 'drop-shadow(0 0 2px #ff0055)' }} />
                                    <Cell fill="#14d9d1" style={{ filter: 'drop-shadow(0 0 2px #14d9d1)' }} />
                                </Pie>
                                <Tooltip contentStyle={{ backgroundColor: 'rgba(0,0,0,0.9)', border: '1px solid #00ffff', color: '#00ffff', borderRadius: '0px', boxShadow: '0 0 10px #00ffff' }} itemStyle={{ color: '#00ffff', fontFamily: 'monospace' }} />
                                <text x="50%" y="50%" dy={8} textAnchor="middle" className="fill-white text-3xl font-mono tracking-widest" style={{ filter: 'drop-shadow(0 0 3px white)' }}>
                                    {data.ja4_malicious_count || 0}
                                </text>
                                <text x="50%" y="65%" dy={5} textAnchor="middle" className="fill-cyan-400 text-[10px] uppercase tracking-[0.2em] font-mono">
                                    THREATS
                                </text>
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Detected Threats List */}
                <div className="flex-1 flex flex-col h-full overflow-hidden">
                    <h4 className="text-sm font-bold text-danger uppercase tracking-wider mb-3 flex items-center gap-2">
                        <Activity size={16} />
                        Active Threats
                    </h4>
                    {/* Constrain height to ensure scrolling within the flex container */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar bg-black/20 rounded border border-white/5 max-h-[350px]">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-black/50 sticky top-0 backdrop-blur-sm z-10">
                                <tr className="text-gray-500 border-b border-border">
                                    <th className="p-2 pl-4">Timestamp</th>
                                    <th className="p-2">Source IP</th>
                                    <th className="p-2">Target</th>
                                    <th className="p-2">SNI / Domain</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                                {maliciousFlows.length > 0 ? maliciousFlows.map((flow) => (
                                    <tr
                                        key={flow.id}
                                        onClick={() => handleInspect(flow.id)}
                                        className="hover:bg-white/5 transition-colors group cursor-pointer"
                                    >
                                        <td className="p-2 pl-4 text-gray-400 text-xs font-mono">{new Date(flow.captured_at).toLocaleTimeString()}</td>
                                        <td className="p-2 text-white font-mono">{flow.src_ip}</td>
                                        <td className="p-2 text-gray-300 font-mono">{flow.dst_ip}</td>
                                        <td className="p-2 text-cyan-300 font-mono text-xs">{flow.sni && flow.sni !== 'N/A' && flow.sni !== 'None' ? flow.sni : (flow.ja4_sni !== 'N/A' ? flow.ja4_sni : '-')}</td>
                                    </tr>
                                )) : (
                                    <tr>
                                        <td colSpan="4" className="p-8 text-center text-gray-600 italic">
                                            No malicious flows detected by JA4 model.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* Scrollable Sub-Tab Navigation */}
            <div className="border-b border-gray-700 overflow-x-auto w-full sticky top-0 bg-background z-10 pt-2">
                <div className="flex space-x-6 pb-2 min-w-max px-2">
                    {TABS.map((tab) => {
                        const Icon = tab.icon;
                        const isActive = activeTabId === tab.id;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTabId(tab.id)}
                                className={`flex items-center gap-2 pb-2 transition-colors ${isActive ? 'text-primary border-b-2 border-primary' : 'text-gray-400 hover:text-white'}`}
                            >
                                <Icon size={16} />
                                <span className="font-bold whitespace-nowrap">{tab.label}</span>
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <KPIWidget
                    title={`Unique ${activeTab.title}s`}
                    value={diversityCount || "0"}
                    subtext={`Distinct ${activeTab.label} Signatures`}
                    icon={activeTab.icon}
                    color="blue"
                />
                <KPIWidget
                    title={`Top ${activeTab.label} Hash`}
                    value={chartData?.[0]?.count || "0"}
                    subtext="Most Frequent Signature"
                    icon={Hash}
                    color="green"
                />

                {/* Technical Construction Card - Replaces 3rd Widget */}
                <div className="card p-4 flex flex-col justify-center border-l-4 border-primary bg-black/40">
                    <div className="flex items-center gap-2 mb-2 text-primary">
                        <Info size={18} />
                        <span className="font-bold text-sm uppercase tracking-wider">Fingerprint Structure</span>
                    </div>
                    <div className="font-mono text-xl text-white tracking-widest mb-2 bg-black/60 p-2 rounded text-center shadow-inner">
                        {activeTab.format.split('_').map((part, i) => (
                            <span key={i} className="mx-0.5">
                                <span className="text-primary">{part}</span>
                                <span className="text-gray-600">{i < activeTab.format.split('_').length - 1 ? '_' : ''}</span>
                            </span>
                        ))}
                    </div>
                    <div className="flex flex-wrap gap-2 justify-center">
                        {activeTab.components.map((comp) => (
                            <div key={comp.id} className="text-[10px] bg-white/5 px-2 py-1 rounded border border-white/10 text-center" title={comp.desc}>
                                <span className="text-primary font-bold">{comp.id}</span>: <span className="text-gray-300">{comp.label}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Chart */}
                <div className="card h-96 flex flex-col">
                    <h3 className="text-xl font-bold text-white mb-1">{activeTab.label} Profile</h3>
                    <p className="text-primary text-sm mb-1 font-mono">{activeTab.desc}</p>
                    <p className="text-gray-400 text-xs mb-4">Distribution of the most observed fingerprints.</p>
                    <div className="flex-1 min-h-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart layout="vertical" data={chartData} barSize={20} margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                                <XAxis type="number" stroke="#666" />
                                <YAxis dataKey="hash" type="category" stroke="#fff" tick={{ fontSize: 11 }} width={150} />
                                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff' }} />
                                <Bar dataKey="count" fill={activeTab.color} radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Detailed Table */}
                <div className="card h-96 flex flex-col">
                    <h3 className="text-xl font-bold text-white mb-2">{activeTab.label} Registry</h3>
                    <p className="text-gray-400 text-sm mb-4">Live feed of unique hashes observed.</p>
                    <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-black sticky top-0">
                                <tr className="text-gray-500 border-b border-border">
                                    <th className="pb-2">Fingerprint Hash</th>
                                    <th className="pb-2 text-right">Count</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                                {chartData.length > 0 ? chartData.map((item, idx) => (
                                    <tr key={idx} className="hover:bg-white/5 transition-colors">
                                        <td className="py-2 text-gray-300 font-mono text-xs break-all pr-2">{item.hash}</td>
                                        <td className="py-2 text-right text-primary font-bold">{item.count}</td>
                                    </tr>
                                )) : (
                                    <tr>
                                        <td colSpan="2" className="py-4 text-center text-gray-600 italic">No {activeTab.label} fingerprints detected yet.</td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Recent Connections for this Fingerprint Type */}
                <div className="card h-96 flex flex-col col-span-1 lg:col-span-2">
                    <h3 className="text-xl font-bold text-white mb-2">Recent {activeTab.label} Connections</h3>
                    <p className="text-gray-400 text-sm mb-4">Latest flows where this fingerprint type was calculated.</p>
                    <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-black sticky top-0">
                                <tr className="text-gray-500 border-b border-border">
                                    <th className="pb-2 pl-2">Time</th>
                                    <th className="pb-2">Source</th>
                                    <th className="pb-2">Destination</th>
                                    <th className="pb-2">SNI / Domain</th>
                                    <th className="pb-2 text-right">Fingerprint Value</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                                {data.recent_features && data.recent_features[activeTabId] && data.recent_features[activeTabId].length > 0 ? (
                                    data.recent_features[activeTabId].map((flow) => (
                                        <tr
                                            key={flow.id}
                                            onClick={() => handleInspect(flow.id)}
                                            className="hover:bg-white/5 transition-colors group cursor-pointer"
                                        >
                                            <td className="py-2 pl-2 text-gray-400 text-xs font-mono">{new Date(flow.captured_at).toLocaleTimeString()}</td>
                                            <td className="py-2 text-white font-mono">{flow.src_ip}</td>
                                            <td className="py-2 text-gray-300 font-mono">{flow.dst_ip}</td>
                                            <td className="py-2 text-cyan-300 font-mono text-xs">{flow.sni && flow.sni !== 'N/A' && flow.sni !== 'None' ? flow.sni : '-'}</td>
                                            <td className="py-2 text-right text-primary font-mono text-xs truncate max-w-[200px]" title={flow.value}>{flow.value}</td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan="5" className="py-8 text-center text-gray-600 italic">No recent {activeTab.label} flows found.</td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* Slide-Over Panel for Local Inspection */}
            <FlowDetailPanel
                flow={selectedFlow}
                loading={detailLoading}
                onClose={() => setSelectedFlow(null)}
            />
        </div>
    );
}
