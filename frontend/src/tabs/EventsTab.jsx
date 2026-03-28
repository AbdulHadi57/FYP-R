import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    AlertTriangle,
    ShieldAlert,
    Activity,
    Info,
    CheckCircle,
    Clock,
    Server,
    Wifi,
    Cpu,
    ChevronDown,
    ExternalLink
} from 'lucide-react';
import FlowDetailPanel from '../components/FlowDetailPanel';

const EventsTab = ({ apiBaseUrl }) => {
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [viewMode, setViewMode] = useState('open'); // 'open', 'resolved', 'system'

    // Filters
    const [filterModule, setFilterModule] = useState('all');
    const [filterConfidence, setFilterConfidence] = useState(0);

    // Resolution Modal State
    const [resolvingId, setResolvingId] = useState(null);
    const [resolutionNote, setResolutionNote] = useState('');

    // Flow Detail State
    const [selectedFlow, setSelectedFlow] = useState(null);
    const [loadingFlow, setLoadingFlow] = useState(false);

    const handleFlowClick = async (flowId) => {
        setLoadingFlow(true);
        setSelectedFlow(null); // Reset to show loading state
        try {
            const response = await axios.get(`${apiBaseUrl}/api/flows/${flowId}`);
            setSelectedFlow(response.data);
        } catch (error) {
            console.error("Error fetching flow details:", error);
        } finally {
            setLoadingFlow(false);
        }
    };

    const fetchEvents = async () => {
        try {
            let url = `${apiBaseUrl}/api/events?status=${viewMode}&min_confidence=${filterConfidence / 100}`;
            if (filterModule !== 'all') {
                url += `&module=${filterModule}`;
            }
            const response = await axios.get(url);
            setEvents(response.data);
        } catch (error) {
            console.error("Error fetching events:", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        setLoading(true);
        fetchEvents();
        const interval = setInterval(fetchEvents, 5000);
        return () => clearInterval(interval);
    }, [apiBaseUrl, viewMode, filterModule, filterConfidence]);

    const getSeverityColor = (severity) => {
        switch (severity?.toLowerCase()) {
            case 'critical': return 'text-red-500 border-red-500/30 bg-red-500/10';
            case 'high': return 'text-orange-500 border-orange-500/30 bg-orange-500/10';
            case 'medium': return 'text-yellow-500 border-yellow-500/30 bg-yellow-500/10';
            case 'info': return 'text-blue-400 border-blue-400/30 bg-blue-400/10';
            default: return 'text-gray-400 border-gray-400/30 bg-gray-400/10';
        }
    };

    const getIcon = (category, severity) => {
        if (severity === 'critical') return <ShieldAlert size={20} />;
        if (category === 'network') return <Wifi size={20} />;
        if (category === 'system') return <Cpu size={20} />;
        if (category === 'compliance') return <CheckCircle size={20} />;
        return <Info size={20} />;
    };

    const handleResolveClick = (eventId) => {
        setResolvingId(eventId);
        setResolutionNote('');
    };

    const confirmResolve = async () => {
        if (!resolvingId) return;

        // Optimistic UI update
        setEvents(prev => prev.filter(e => e.id !== resolvingId));
        setResolvingId(null); // Close modal immediately

        try {
            await axios.post(`${apiBaseUrl}/api/events/${resolvingId}/resolve`, {
                note: resolutionNote || "Resolved without notes."
            });
            fetchEvents();
        } catch (error) {
            console.error("Error resolving event:", error);
        }
    };

    const criticalCount = events.filter(e => e.severity === 'critical').length;

    // Module Badge Helper
    const getModuleBadge = (source) => {
        switch (source?.toLowerCase()) {
            case 'ja4': return <span className="bg-purple-500/10 text-purple-400 border border-purple-500/20 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wider">JA4 MODULE</span>;
            case 'doh': return <span className="bg-pink-500/10 text-pink-400 border border-pink-500/20 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wider">DoH MODULE</span>;
            case 'apt': return <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wider">APT MODULE</span>;
            case 'system': return <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wider">SYSTEM LOG</span>;
            default: return <span className="bg-gray-700/30 text-gray-400 border border-gray-600/30 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wider">GENERAL</span>;
        }
    };

    return (
        <div className="space-y-6 h-full flex flex-col p-2 relative">

            {/* Header Tabs (Open vs Resolved) */}
            {/* Header: Filters & Controls */}
            <div className="flex flex-col xl:flex-row gap-4 justify-between items-start xl:items-center border-b border-white/10 pb-6">

                {/* Left Side: View Mode & Advanced Filters */}
                <div className="flex flex-col md:flex-row gap-4 w-full xl:w-auto">

                    {/* View Mode Tabs */}
                    <div className="flex gap-1 p-1 bg-black/40 rounded-lg border border-white/10 overflow-x-auto">
                        {['open', 'resolved', 'system'].map((mode) => (
                            <button
                                key={mode}
                                onClick={() => setViewMode(mode)}
                                className={`px-4 py-2 rounded-md text-sm font-medium transition-all whitespace-nowrap flex items-center gap-2 ${viewMode === mode
                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                                    }`}
                            >
                                {mode === 'open' && <ShieldAlert size={14} />}
                                {mode === 'resolved' && <CheckCircle size={14} />}
                                {mode === 'system' && <Cpu size={14} />}
                                {mode.charAt(0).toUpperCase() + mode.slice(1)}
                                {mode === 'open' && criticalCount > 0 && <span className="bg-red-500 text-black text-[10px] px-1.5 py-0.5 rounded-full ml-1">{criticalCount}</span>}
                            </button>
                        ))}
                    </div>

                    {/* Advanced Filters */}
                    <div className="flex gap-4 items-center flex-wrap">
                        {/* Module Select */}
                        <div className="relative group">
                            <select
                                value={filterModule}
                                onChange={(e) => setFilterModule(e.target.value)}
                                className="appearance-none bg-[#0a0a0a] border border-white/10 rounded-lg pl-4 pr-10 py-2 text-sm text-gray-300 focus:outline-none focus:border-cyan-500/50 hover:border-white/20 transition-colors cursor-pointer w-[180px]"
                            >
                                <option value="all">All Modules</option>
                                <option value="ja4">JA4 Fingerprinting</option>
                                <option value="doh">DNS over HTTPS</option>
                                <option value="apt">APT Detection</option>
                            </select>
                            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 group-hover:text-cyan-400 transition-colors pointer-events-none" />
                        </div>

                        {/* Confidence Slider */}
                        <div className="flex items-center gap-3 bg-black/40 px-4 py-2 rounded-lg border border-white/10 h-[38px]">
                            <span className="text-xs text-gray-400 uppercase tracking-wider">Conf</span>
                            <input
                                type="range"
                                min="0"
                                max="100"
                                step="5"
                                value={filterConfidence}
                                onChange={(e) => setFilterConfidence(Number(e.target.value))}
                                className="w-24 h-1 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                            />
                            <span className="text-xs font-mono text-cyan-400 min-w-[34px] text-right">{filterConfidence}%</span>
                        </div>
                    </div>
                </div>

                {/* Right Side: Live Indicator */}
                <div className="text-xs text-gray-500 font-mono flex items-center gap-2 self-end xl:self-center bg-black/20 px-3 py-1 rounded-full border border-white/5">
                    <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse"></span>
                    LIVE FEED
                </div>
            </div>

            {/* Events Feed */}
            <div className={`flex-1 overflow-y-auto custom-scrollbar space-y-4 pr-2 pb-4 ${resolvingId ? 'opacity-30 pointer-events-none' : ''}`}>
                {loading ? (
                    <div className="flex flex-col items-center justify-center h-full text-cyan-500/50 animate-pulse gap-4">
                        <div className="relative">
                            <div className="w-12 h-12 rounded-full border-2 border-cyan-500/30 border-t-cyan-400 animate-spin"></div>
                        </div>
                        <span className="font-mono text-sm tracking-widest uppercase">Syncing Events...</span>
                    </div>
                ) : events.length > 0 ? (
                    events.map((event, idx) => (
                        <div key={event.id}
                            className="group relative pl-8 pb-2 animate-in fade-in slide-in-from-bottom-4 duration-500"
                            style={{ animationDelay: `${idx * 50}ms` }}
                        >
                            {/* Timeline Line */}
                            <div className={`absolute left-[11px] top-8 bottom-[-16px] w-[1px] group-last:bottom-auto group-last:h-0 transition-colors duration-500 bg-gradient-to-b from-gray-700 to-transparent`}></div>

                            {/* Dot */}
                            <div className={`absolute left-[3px] top-6 w-4 h-4 rounded-full border-2 z-10 bg-black flex items-center justify-center ${viewMode === 'open' ? 'border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' :
                                viewMode === 'resolved' ? 'border-emerald-500' : 'border-cyan-500'
                                }`}>
                                <div className={`w-1.5 h-1.5 rounded-full ${viewMode === 'open' ? 'bg-red-500 animate-pulse' : viewMode === 'resolved' ? 'bg-emerald-500' : 'bg-cyan-500'}`}></div>
                            </div>

                            <div className={`card p-5 border backdrop-blur-md transition-all duration-300 hover:translate-x-1 group-hover:border-opacity-50 ${viewMode === 'open' ? 'border-red-500/30 bg-gradient-to-r from-red-950/20 via-black/40 to-black/20' :
                                viewMode === 'resolved' ? 'border-emerald-500/10 bg-black/20' :
                                    'border-cyan-500/10 bg-black/20'
                                }`}>
                                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-3">
                                    <div className="flex items-start gap-4 flex-1">
                                        <div className={`p-2 rounded-lg mt-1 shadow-lg ${viewMode === 'open' ? 'bg-red-500/10 text-red-400' :
                                            viewMode === 'resolved' ? 'bg-emerald-500/10 text-emerald-400' :
                                                'bg-cyan-500/10 text-cyan-400'
                                            }`}>
                                            {getIcon(event.category, event.severity)}
                                        </div>
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-1 flex-wrap">
                                                <h4 className="font-bold text-lg tracking-tight text-white">{event.title}</h4>
                                                {getModuleBadge(event.module_source)}
                                                {event.confidence != null && event.confidence > 0 && (
                                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${event.confidence > 0.8 ? 'border-red-500/50 text-red-400' : 'border-yellow-500/50 text-yellow-400'
                                                        }`}>
                                                        {Math.round(event.confidence * 100)}% CONFIDENCE
                                                    </span>
                                                )}
                                            </div>
                                            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-gray-500 font-mono mt-1">
                                                <span className="flex items-center gap-1.5">
                                                    <Clock size={12} className="text-cyan-500/50" />
                                                    {new Date(event.timestamp).toLocaleString()}
                                                </span>
                                                <span className="text-gray-500">ID: {event.id.replace('evt_flow_', '')}</span>
                                                {event.flow_id && (
                                                    <span
                                                        onClick={() => handleFlowClick(event.flow_id)}
                                                        className="text-cyan-600 hover:text-cyan-400 cursor-pointer hover:underline decoration-dotted transition-colors ml-2"
                                                    >
                                                        Flow #{event.flow_id}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Action Button */}
                                    {viewMode === 'open' && (
                                        <button
                                            onClick={() => handleResolveClick(event.id)}
                                            className="whitespace-nowrap flex items-center gap-2 px-4 py-2 bg-emerald-500/10 hover:bg-emerald-500 text-emerald-500 hover:text-black border border-emerald-500/30 rounded-lg transition-all duration-300 font-bold text-xs tracking-wider shadow-[0_0_10px_rgba(16,185,129,0.1)] hover:shadow-[0_0_20px_rgba(16,185,129,0.4)]"
                                        >
                                            <CheckCircle size={14} /> MARK AS RESOLVED
                                        </button>
                                    )}
                                </div>

                                <p className="text-gray-300 text-sm leading-relaxed pl-[3.25rem] border-l-2 border-white/5 ml-1 py-1 pr-4">
                                    {event.message}
                                </p>

                                {/* Recommended Action Area */}
                                <div className="ml-[3.5rem] mt-4 flex items-center gap-3">
                                    <div className={`h-8 w-1 rounded-full ${viewMode === 'open' ? 'bg-red-500/50' : viewMode === 'resolved' ? 'bg-emerald-500/50' : 'bg-cyan-500/50'}`}></div>
                                    <div>
                                        <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest block mb-0.5">Recommended Response</span>
                                        <span className={`text-sm font-medium ${viewMode === 'open' ? 'text-white' : 'text-gray-400 italic'}`}>
                                            {event.recommended_action || "No actions required"}
                                        </span>
                                    </div>
                                </div>

                                {/* Resolution Note Display */}
                                {viewMode === 'resolved' && event.resolution_note && (
                                    <div className="ml-[3.5rem] mt-4 bg-white/5 border border-white/10 p-3 rounded-md">
                                        <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest block mb-1">Resolution Note</span>
                                        <p className="text-xs text-gray-300 font-mono">"{event.resolution_note}"</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))
                ) : (
                    <div className="text-center py-32 flex flex-col items-center opacity-50">
                        <CheckCircle size={48} className="text-gray-600 mb-4" />
                        <h3 className="text-xl font-bold text-gray-500">No {viewMode.replace('_', ' ')} events</h3>
                    </div>
                )}
            </div>

            {/* Resolution Modal */}
            {resolvingId && (
                <div className="absolute inset-0 z-50 flex items-center justify-center p-4">
                    <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" onClick={() => setResolvingId(null)}></div>
                    <div className="bg-gray-900 border border-emerald-500/30 rounded-xl p-6 w-full max-w-md shadow-[0_0_50px_rgba(16,185,129,0.2)] relative z-10 animate-in fade-in zoom-in duration-200">
                        <h3 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                            <CheckCircle className="text-emerald-500" size={20} /> Resolve Security Event
                        </h3>
                        <p className="text-sm text-gray-400 mb-4">Add a resolution note/commit message for the audit log.</p>

                        <textarea
                            value={resolutionNote}
                            onChange={(e) => setResolutionNote(e.target.value)}
                            placeholder="e.g., False positive confirmed by analyst..."
                            className="w-full bg-black/50 border border-white/10 rounded-lg p-3 text-white text-sm focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 h-24 mb-4 resize-none"
                            autoFocus
                        />

                        <div className="flex gap-2 justify-end">
                            <button
                                onClick={() => setResolvingId(null)}
                                className="px-4 py-2 rounded-lg text-sm text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={confirmResolve}
                                className="px-4 py-2 bg-emerald-500 text-black font-bold text-sm rounded-lg hover:bg-emerald-400 transition-colors shadow-lg shadow-emerald-500/20"
                            >
                                Confirm Resolution
                            </button>
                        </div>
                    </div>
                </div>
            )}


            {/* Flow Detail Panel */}
            <FlowDetailPanel
                flow={selectedFlow}
                loading={loadingFlow}
                onClose={() => {
                    setSelectedFlow(null);
                    setLoadingFlow(false);
                }}
            />
        </div>
    );
};

export default EventsTab;
