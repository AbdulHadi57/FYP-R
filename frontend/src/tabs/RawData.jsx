import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Search, Download, Filter, X, Server, Clock, Activity, Shield } from 'lucide-react';
import FlowDetailPanel from '../components/FlowDetailPanel';


export default function RawData({ selectedFlowId }) {
    const [flows, setFlows] = useState([]);
    const [search, setSearch] = useState('');
    const [filters, setFilters] = useState({});
    const [loading, setLoading] = useState(false);
    const [selectedFlow, setSelectedFlow] = useState(null);
    const [detailLoading, setDetailLoading] = useState(false);

    // Auto-open selected flow if passed
    useEffect(() => {
        if (selectedFlowId) {
            handleRowClick(selectedFlowId);
        }
    }, [selectedFlowId]);

    const fetchFlows = async (isPoll = false) => {
        if (!isPoll) setLoading(true);
        try {
            const params = new URLSearchParams();
            if (search) params.append('search', search);

            // Add multi-column filters as JSON string
            if (Object.keys(filters).length > 0) {
                params.append('filters', JSON.stringify(filters));
            }

            const isFiltering = search || Object.keys(filters).length > 0;

            // Poll logic: Only append if NOT filtering and we have data
            if (isPoll && !isFiltering && flows.length > 0) {
                const maxId = Math.max(...flows.map(f => f.id));
                params.append('min_id', maxId);
                params.append('limit', 50);

                const res = await axios.get(`/api/flows?${params.toString()}`);
                const newFlows = res.data;
                if (newFlows.length > 0) {
                    setFlows(prev => [...newFlows, ...prev].slice(0, 500));
                }
            } else {
                params.append('limit', 200);
                const res = await axios.get(`/api/flows?${params.toString()}`);
                setFlows(res.data);
            }
        } catch (error) {
            console.error("Error fetching flows:", error);
        } finally {
            if (!isPoll) setLoading(false);
        }
    };

    useEffect(() => {
        fetchFlows();
        const interval = setInterval(() => fetchFlows(true), 3000);
        return () => clearInterval(interval);
    }, [search, filters]);

    const handleFilterChange = (col, val) => {
        setFilters(prev => {
            const next = { ...prev, [col]: val };
            if (!val) delete next[col];
            return next;
        });
    };

    const handleRowClick = async (id) => {
        setDetailLoading(true);
        setSelectedFlow(null);
        try {
            const res = await axios.get(`/api/flows/${id}`);
            setSelectedFlow(res.data);
        } catch (error) {
            console.error("Error fetching flow details:", error);
        } finally {
            setDetailLoading(false);
        }
    };

    const closePanel = () => setSelectedFlow(null);

    const downloadCSV = () => {
        if (!flows.length) return;
        const headers = Object.keys(flows[0]).join(',');
        const rows = flows.map(f => Object.values(f).join(','));
        const csvContent = "data:text/csv;charset=utf-8," + [headers, ...rows].join('\n');
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", "aegisnet_flows.csv");
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    // Local state for the "Add Filter" inputs
    const [newFilterCol, setNewFilterCol] = useState('src_ip');
    const [newFilterVal, setNewFilterVal] = useState('');

    const addFilter = () => {
        if (!newFilterCol || !newFilterVal) return;
        setFilters(prev => ({ ...prev, [newFilterCol]: newFilterVal }));
        setNewFilterVal(''); // Clear input after adding
    };

    const removeFilter = (key) => {
        setFilters(prev => {
            const next = { ...prev };
            delete next[key];
            return next;
        });
    };

    const COLUMNS = [
        { id: 'id', label: 'Flow ID' },
        { id: 'src_ip', label: 'Source IP' },
        { id: 'dst_ip', label: 'Dest IP' },
        { id: 'src_port', label: 'Src Port' },
        { id: 'dst_port', label: 'Dst Port' },
        { id: 'protocol', label: 'Protocol' },
        { id: 'ja4_pred', label: 'JA4 Verdict' },
        { id: 'doh_pred', label: 'DoH Verdict' },
        { id: 'apt_pred', label: 'APT Verdict' },
        { id: 'verdict', label: 'Flow Verdict' },
        { id: 'total_packets', label: 'Packet Count' },
        { id: 'flow_duration', label: 'Duration' },
        { id: 'severity', label: 'Severity' }
    ];

    const TABLE_COLS = [
        { id: 'id', label: 'ID', width: 'w-16' },
        { id: 'captured_at', label: 'Timestamp', width: 'w-32' },
        { id: 'src_ip', label: 'Source IP', width: 'w-32' },
        { id: 'src_port', label: 'Port', width: 'w-20' },
        { id: 'dst_ip', label: 'Dest IP', width: 'w-32' },
        { id: 'sni', label: 'SNI / Domain', width: 'w-48' },
        { id: 'dst_port', label: 'Dst Port', width: 'w-24' },
        { id: 'protocol', label: 'Proto', width: 'w-20' },
        { id: 'ja4_pred', label: 'JA4', width: 'w-24' },
        { id: 'doh_pred', label: 'DoH', width: 'w-24' },
        { id: 'apt_pred', label: 'APT', width: 'w-24' },
        { id: 'verdict', label: 'Verdict', width: 'w-24' },
        { id: 'confidence', label: 'Conf', width: 'w-20' },
        { id: 'total_packets', label: 'Pkts', width: 'w-24' },
        { id: 'flow_duration', label: 'Dur (s)', width: 'w-24' },
    ];

    const getProtoName = (p) => {
        if (p === 6) return 'TCP';
        if (p === 17) return 'UDP';
        if (p === 1) return 'ICMP';
        return p;
    };

    return (
        <div className="space-y-6 relative">
            <div className="card">
                {/* Header Row: Title + Filter Controls */}
                <div className="flex flex-col gap-4 mb-6">
                    <div className="flex justify-between items-center">
                        <h3 className="text-xl font-bold text-white">Traffic Inspector</h3>
                        <div className="flex items-center gap-2">
                            <input
                                type="text"
                                placeholder="Global Search..."
                                className="bg-[#0a0a0a] border border-white/10 rounded px-3 py-2 text-sm focus:outline-none focus:border-primary/50 w-48 text-gray-300 placeholder-gray-600"
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                            />
                            <button onClick={downloadCSV} className="btn bg-primary/20 text-primary hover:bg-primary hover:text-black flex items-center gap-2 transition-colors border border-primary/20">
                                <Download size={16} /> CSV
                            </button>
                        </div>
                    </div>

                    {/* Filter Bar */}
                    <div className="bg-surface/50 p-4 rounded-lg border border-white/5 flex flex-wrap gap-4 items-end">
                        <div className="flex flex-col gap-1">
                            <label className="text-xs text-gray-500 uppercase font-bold">Column</label>
                            <select
                                className="bg-[#0a0a0a] border border-white/10 rounded px-3 py-2 text-sm text-gray-300 focus:border-primary/50 focus:outline-none w-40"
                                value={newFilterCol}
                                onChange={(e) => { setNewFilterCol(e.target.value); setNewFilterVal(''); }}
                            >
                                {COLUMNS.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
                            </select>
                        </div>

                        <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
                            <label className="text-xs text-gray-500 uppercase font-bold">Value</label>
                            {['verdict', 'ja4_pred', 'doh_pred', 'apt_pred'].includes(newFilterCol) ? (
                                <select
                                    className="bg-[#0a0a0a] border border-white/10 rounded px-3 py-2 text-sm text-gray-300 focus:border-primary/50 focus:outline-none w-full"
                                    value={newFilterVal}
                                    onChange={(e) => setNewFilterVal(e.target.value)}
                                >
                                    <option value="">Select Verdict...</option>
                                    <option value="malicious">Malicious</option>
                                    <option value="benign">Benign</option>
                                    <option value="none">None</option>
                                </select>
                            ) : newFilterCol === 'protocol' ? (
                                <select
                                    className="bg-[#0a0a0a] border border-white/10 rounded px-3 py-2 text-sm text-gray-300 focus:border-primary/50 focus:outline-none w-full"
                                    value={newFilterVal}
                                    onChange={(e) => setNewFilterVal(e.target.value)}
                                >
                                    <option value="">Select Protocol...</option>
                                    <option value="TCP">TCP</option>
                                    <option value="UDP">UDP</option>
                                    <option value="ICMP">ICMP</option>
                                </select>
                            ) : (
                                <input
                                    type="text"
                                    placeholder={`Filter by ${COLUMNS.find(c => c.id === newFilterCol)?.label}...`}
                                    className="bg-[#0a0a0a] border border-white/10 rounded px-3 py-2 text-sm text-gray-300 focus:border-primary/50 focus:outline-none w-full placeholder-gray-600"
                                    value={newFilterVal}
                                    onChange={(e) => setNewFilterVal(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && addFilter()}
                                />
                            )}
                        </div>

                        <button
                            onClick={addFilter}
                            disabled={!newFilterVal}
                            className="bg-primary text-black px-4 py-2 rounded font-bold text-sm hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed h-[38px]"
                        >
                            ADD FILTER
                        </button>
                    </div>

                    {/* Active Filters Chips */}
                    {Object.keys(filters).length > 0 && (
                        <div className="flex flex-wrap gap-2 items-center">
                            <span className="text-xs text-gray-500 uppercase mr-2">Active Filters:</span>
                            {Object.entries(filters).map(([key, val]) => (
                                <div key={key} className="bg-primary/10 border border-primary/30 rounded-full px-3 py-1 flex items-center gap-2 text-xs text-primary">
                                    <span className="font-bold text-white/70">{COLUMNS.find(c => c.id === key)?.label || key}:</span>
                                    <span className="text-white">{val}</span>
                                    <button onClick={() => removeFilter(key)} className="hover:text-white transition-colors"><X size={14} /></button>
                                </div>
                            ))}
                            <button
                                onClick={() => setFilters({})}
                                className="text-xs text-red-400 hover:text-red-300 ml-auto underline"
                            >
                                Clear All
                            </button>
                        </div>
                    )}
                </div>

                {/* Simplified Table Container - Removed rigid height and backgrounds */}
                <div className="w-full overflow-x-auto">
                    <table className="w-full text-left text-sm text-gray-300">
                        <thead className="bg-[#0f0f0f] border-b border-gray-700 font-mono text-xs uppercase tracking-wider">
                            <tr>
                                {TABLE_COLS.map(col => (
                                    <th key={col.id} className={`p-3 ${col.width}`}>{col.label}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border/30">
                            {loading && flows.length === 0 ? (
                                <tr><td colSpan={TABLE_COLS.length} className="text-center py-8 text-gray-500">Loading data...</td></tr>
                            ) : flows.map((flow) => (
                                <tr
                                    key={flow.id}
                                    onClick={() => handleRowClick(flow.id)}
                                    className={`cursor-pointer transition-colors group ${selectedFlow?.id === flow.id ? 'bg-primary/10 border-l-2 border-primary' : 'hover:bg-white/5 border-l-2 border-transparent'
                                        } ${flow.verdict === 'malicious' ? 'bg-red-500/5' : ''}`}
                                >
                                    <td className="py-3 pl-3 font-mono text-xs text-gray-500">#{flow.id}</td>
                                    <td className="py-3 text-gray-400">{flow.captured_at?.split('T')[1]?.split('.')[0]}</td>
                                    <td className="py-3 font-mono text-white/90">{flow.src_ip}</td>
                                    <td className="py-3 font-mono text-gray-500">{flow.src_port}</td>
                                    <td className="py-3 font-mono text-white/90">{flow.dst_ip}</td>
                                    <td className="py-3 font-mono text-gray-400 text-xs truncate max-w-[200px] text-center" title={flow.sni}>{flow.sni || '-'}</td>
                                    <td className="py-3 font-mono text-gray-500">{flow.dst_port}</td>
                                    <td className="py-3">
                                        <span className="bg-white/10 px-1.5 py-0.5 rounded text-[10px] text-gray-300">{getProtoName(flow.protocol)}</span>
                                    </td>
                                    <td className="py-3 font-mono text-xs text-gray-400 capitalize">{flow.ja4_pred !== 'none' ? flow.ja4_pred : '-'}</td>
                                    <td className="py-3 font-mono text-xs text-gray-400 capitalize">{flow.doh_pred !== 'none' ? flow.doh_pred : '-'}</td>
                                    <td className="py-3 font-mono text-xs text-gray-400 capitalize">{flow.apt_pred !== 'none' ? flow.apt_pred : '-'}</td>
                                    <td className="py-3">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${flow.verdict === 'malicious' ? 'bg-red-500 text-black shadow-[0_0_10px_rgba(239,68,68,0.4)]' : 'bg-emerald-500/20 text-emerald-400'
                                            }`}>
                                            {flow.verdict}
                                        </span>
                                    </td>
                                    <td className="py-3 text-gray-400 text-xs">{(flow.confidence * 100).toFixed(0)}%</td>
                                    <td className="py-3 text-gray-400">{flow.total_packets}</td>
                                    <td className="py-3 text-gray-400">{flow.flow_duration.toFixed(2)}s</td>
                                </tr>
                            ))}
                            {flows.length === 0 && !loading && (
                                <tr><td colSpan={TABLE_COLS.length} className="text-center py-12 text-gray-600 italic">No flows match your filter criteria.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            <FlowDetailPanel
                flow={selectedFlow}
                loading={detailLoading}
                onClose={closePanel}
            />
        </div>
    );
}
