import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
    ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';
import KPIWidget from '../../components/KPIWidget';
import { Shield, Lock, Activity, Globe, Eye, AlertTriangle } from 'lucide-react';

const COLORS = ['#00C49F', '#FFBB28', '#FF8042', '#0088FE'];
const STATUS_COLORS = { malicious: '#ff4b4b', benign: '#00cc96' };

// Update to accept navigation prop not needed for this change, but keeping for compatibility
import FlowDetailPanel from '../../components/FlowDetailPanel';

export default function DoHModule() {
    const [data, setData] = useState(null);
    const [selectedFlow, setSelectedFlow] = useState(null);
    const [detailLoading, setDetailLoading] = useState(false);
    const [isThreatsExpanded, setIsThreatsExpanded] = useState(true);

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
        const interval = setInterval(fetchData, 3000); // Auto-refresh every 3s
        return () => clearInterval(interval);
    }, []);

    const handleFlowClick = async (id) => {
        setDetailLoading(true);
        setSelectedFlow(null);
        try {
            const res = await axios.get(`/api/flows/${id}`);
            // The panel expects { features: ... }, but api returns flat structure mixed with json
            // Adapt if needed, but existing panel seems to handle flat flow object if we map correctly
            // FlowDetailPanel checks flow.features. Let's see how RawData passes it.
            // RawData passes: setSelectedFlow(res.data). res.data from /api/flows/{id} returns { id, features: {...} }
            // So we are good.
            setSelectedFlow(res.data);
        } catch (error) {
            console.error("Error fetching flow details:", error);
        } finally {
            setDetailLoading(false);
        }
    };

    if (!data) return <div className="text-white">Loading DoH Analysis...</div>;

    const dohCount = data.doh_stats?.length || 0;
    const avgResponseTime = dohCount > 0
        ? (data.doh_stats.reduce((acc, curr) => acc + curr.response_time, 0) / dohCount).toFixed(2)
        : "0";

    const maliciousDoHFlows = data.doh_malicious_flows || [];

    // Stage 1 Data
    const stage1Data = [
        { name: 'Encrypted DNS (DoH)', value: data.doh_detection_stats?.detected || 0 },
        { name: 'Standard Traffic', value: data.doh_detection_stats?.non_doh || 0 }
    ];

    // Stage 2 Data
    const stage2Data = [
        { name: 'Malicious DoH', value: data.doh_classification_stats?.malicious || 0 },
        { name: 'Benign DoH', value: data.doh_classification_stats?.benign || 0 }
    ];

    return (
        <div className="space-y-6 relative">
            {/* Stats Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <KPIWidget
                    title="DoH Tunnels"
                    value={dohCount}
                    subtext="Potential Encrypted DNS Flows"
                    icon={Lock}
                    color="yellow"
                />
                <KPIWidget
                    title="Avg Latency"
                    value={`${avgResponseTime}ms`}
                    subtext="DoH Response Time"
                    icon={Activity}
                    color="blue"
                />
                <KPIWidget
                    title="Malicious DoH"
                    value={data.doh_classification_stats?.malicious || 0}
                    subtext="Confirmed Threats"
                    icon={AlertTriangle}
                    color="red"
                />
            </div>

            {/* Two-Stage AI Pipeline Visualization */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="card h-80 flex flex-col">
                    <div className="flex items-center gap-2 mb-2">
                        <div className="bg-blue-500/20 p-2 rounded text-blue-400"><Eye size={20} /></div>
                        <div>
                            <h3 className="text-lg font-bold text-white">Stage 1: Traffic Detection</h3>
                            <p className="text-gray-400 text-xs">Model A: Classify DoH vs Non-DoH</p>
                        </div>
                    </div>
                    <div className="flex-1 min-h-0 flex items-center">
                        <div className="w-1/2 h-full relative">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={[{ value: 1 }]}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={61}
                                        dataKey="value"
                                        stroke="none"
                                        fill="rgba(255,255,255,0.1)"
                                        isAnimationActive={false}
                                        legendType="none"
                                    />
                                    <Pie
                                        data={stage1Data}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={55}
                                        outerRadius={65}
                                        paddingAngle={5}
                                        cornerRadius={2}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {stage1Data.map((entry, index) => (
                                            <Cell
                                                key={`cell-${index}`}
                                                fill={index === 0 ? '#f59e0b' : '#a1a1aa'}
                                                style={{ filter: `drop-shadow(0 0 4px ${index === 0 ? '#f59e0b' : 'rgba(255,255,255,0.1)'})` }}
                                            />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={{ backgroundColor: 'rgba(0,0,0,0.9)', border: '1px solid #f59e0b', color: '#f59e0b', borderRadius: '0px', boxShadow: '0 0 10px #f59e0b' }} itemStyle={{ color: '#f59e0b', fontFamily: 'monospace' }} />
                                    <text x="50%" y="50%" dy={0} textAnchor="middle" dominantBaseline="middle" className="fill-white text-xl font-mono tracking-widest" style={{ filter: 'drop-shadow(0 0 3px white)' }}>
                                        {data.doh_detection_stats?.detected || 0}
                                    </text>
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                        <div className="w-1/2 pl-4 flex flex-col justify-center gap-4 border-l border-white/10">
                            <div>
                                <div className="text-xs text-gray-400 uppercase tracking-wider">Total Evaluated</div>
                                <div className="text-2xl font-bold text-white font-mono">
                                    {(data.doh_detection_stats?.detected || 0) + (data.doh_detection_stats?.non_doh || 0)}
                                </div>
                            </div>
                            <div>
                                <div className="text-xs text-gray-400 uppercase tracking-wider">Detected DoH</div>
                                <div className="text-xl font-bold text-amber-500 font-mono">
                                    {data.doh_detection_stats?.detected || 0}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Stage 2 Chart Only */}
                <div className="card h-80 flex flex-col">
                    <div className="flex items-center gap-2 mb-2">
                        <div className="bg-red-500/20 p-2 rounded text-red-400"><AlertTriangle size={20} /></div>
                        <div>
                            <h3 className="text-lg font-bold text-white">Stage 2: Threat Classification</h3>
                            <p className="text-gray-400 text-xs">Model B: Malicious vs Benign (DoH Only)</p>
                        </div>
                    </div>
                    <div className="flex-1 min-h-0 flex items-center">
                        <div className="w-1/2 h-full relative">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={[{ value: 1 }]}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={61}
                                        dataKey="value"
                                        stroke="none"
                                        fill="rgba(255,255,255,0.1)"
                                        isAnimationActive={false}
                                        legendType="none"
                                    />
                                    <Pie
                                        data={stage2Data}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={55}
                                        outerRadius={65}
                                        paddingAngle={5}
                                        cornerRadius={2}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        <Cell key="malicious" fill="#ff0055" style={{ filter: 'drop-shadow(0 0 4px #ff0055)' }} />
                                        <Cell key="benign" fill="#00ffff" style={{ filter: 'drop-shadow(0 0 4px #00ffff)' }} />
                                    </Pie>
                                    <Tooltip contentStyle={{ backgroundColor: 'rgba(0,0,0,0.9)', border: '1px solid #ff0055', color: '#ff0055', borderRadius: '0px', boxShadow: '0 0 10px #ff0055' }} itemStyle={{ color: '#ff0055', fontFamily: 'monospace' }} />
                                    <text x="50%" y="50%" dy={0} textAnchor="middle" dominantBaseline="middle" className="fill-white text-xl font-mono tracking-widest" style={{ filter: 'drop-shadow(0 0 3px white)' }}>
                                        {data.doh_classification_stats?.malicious || 0}
                                    </text>
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                        <div className="w-1/2 pl-4 flex flex-col justify-center gap-4 border-l border-white/10">
                            <div>
                                <div className="text-xs text-gray-400 uppercase tracking-wider">Processed</div>
                                <div className="text-2xl font-bold text-white font-mono">
                                    {(data.doh_classification_stats?.malicious || 0) + (data.doh_classification_stats?.benign || 0)}
                                </div>
                            </div>
                            <div>
                                <div className="text-xs text-gray-400 uppercase tracking-wider">Malicious</div>
                                <div className="text-xl font-bold text-red-500 font-mono">
                                    {data.doh_classification_stats?.malicious || 0}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* New Malicious Flows Section */}
            <div className="card relative transition-all duration-300">
                <div className="sticky top-0 z-10 bg-surface/95 backdrop-blur py-2 border-b border-white/10 flex justify-between items-center mb-2 -mx-4 px-6 -mt-4 rounded-t-lg">
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                        <Shield className="text-red-500" size={20} />
                        Detected Malicious Flows
                        <span className="text-xs text-gray-500 font-normal ml-2">({maliciousDoHFlows.length})</span>
                    </h3>
                    <button
                        onClick={() => setIsThreatsExpanded(!isThreatsExpanded)}
                        className="p-1 hover:bg-white/10 rounded transition-colors text-primary flex items-center gap-1 text-xs font-bold uppercase"
                    >
                        {isThreatsExpanded ? 'Collapse' : 'Expand'}
                    </button>
                </div>

                {isThreatsExpanded && (
                    <div className="w-full overflow-x-auto max-h-[500px] overflow-y-auto custom-scrollbar">
                        <table className="w-full text-left text-sm text-gray-300">
                            <thead>
                                <tr className="text-gray-500 border-b border-border">
                                    <th className="pb-3 pl-2">Flow ID</th>
                                    <th className="pb-3">Timestamp</th>
                                    <th className="pb-3">Source IP</th>
                                    <th className="pb-3">Dest IP</th>
                                    <th className="pb-3 text-right pr-2">Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/50">
                                {maliciousDoHFlows.map(flow => (
                                    <tr
                                        key={flow.id}
                                        className="hover:bg-white/5 cursor-pointer transition-colors"
                                        onClick={() => handleFlowClick(flow.id)}
                                    >
                                        <td className="py-3 pl-2 font-mono text-xs text-red-400">#{flow.id}</td>
                                        <td className="py-3">{flow.captured_at?.split('T')[1]?.split('.')[0]}</td>
                                        <td className="py-3 font-mono text-gray-300">{flow.src_ip}</td>
                                        <td className="py-3 font-mono text-red-300">{flow.dst_ip}</td>
                                        <td className="py-3 text-right pr-2">
                                            <button className="text-xs bg-primary/20 text-primary px-3 py-1 rounded hover:bg-primary hover:text-black transition-colors">
                                                VIEW
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {maliciousDoHFlows.length === 0 && (
                                    <tr>
                                        <td colSpan="5" className="py-8 text-center text-gray-600 italic">
                                            No malicious threats detected in current window.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* DoH Detection Chart */}
            <div className="card h-[400px] flex flex-col">
                <h3 className="text-xl font-bold text-white mb-2">DoH Traffic Forensics</h3>
                <p className="text-gray-400 text-sm mb-4">Response Time vs Throughput scatter plot.</p>
                <div className="flex-1 min-h-0">
                    <ResponsiveContainer width="100%" height="100%">
                        <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                            <XAxis type="number" dataKey="response_time" name="Response Time" unit="ms" stroke="#666" />
                            <YAxis type="number" dataKey="throughput" name="Throughput" unit="B/s" stroke="#666" />
                            <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff' }} />
                            <Scatter name="DoH Flows" data={data.doh_stats || []} fill="#ffbb28" />
                        </ScatterChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Slide-over Detail Panel */}
            <FlowDetailPanel
                flow={selectedFlow}
                loading={detailLoading}
                onClose={() => setSelectedFlow(null)}
            />
        </div>
    );
}
