import React from 'react';
import { X, Shield, Clock, Activity } from 'lucide-react';

export default function FlowDetailPanel({ flow, loading, onClose }) {
    if (!flow && !loading) return null;

    const getProtoName = (p) => {
        if (p === 6) return 'TCP';
        if (p === 17) return 'UDP';
        if (p === 1) return 'ICMP';
        return p;
    };

    return (
        <div className="fixed inset-y-0 right-0 w-full md:w-1/3 bg-surface border-l border-border shadow-2xl z-50 transform transition-transform duration-300 ease-in-out p-6 font-sans flex flex-col">
            {loading && !flow ? (
                <div className="flex items-center justify-center h-full text-primary">Loading details...</div>
            ) : flow && (
                <div className="relative h-full flex flex-col">
                    {/* Sticky Header */}
                    <div className="sticky top-0 bg-surface z-10 pb-6 mb-2 border-b border-border/50 pt-1">
                        <div className="flex justify-between items-start">
                            <div>
                                <div className="flex items-center gap-2 mb-2">
                                    <Shield size={20} className={flow.features?.verdict === 'malicious' ? 'text-danger' : 'text-success'} />
                                    <h2 className="text-2xl font-bold text-white">Flow #{flow.id}</h2>
                                </div>
                                <p className="text-sm text-gray-500">
                                    Captured: {flow.features?.timestamp ? new Date(flow.features.timestamp).toLocaleString() : 'N/A'}
                                </p>
                            </div>
                            <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors bg-black/20 p-2 rounded-full hover:bg-white/10">
                                <X size={24} />
                            </button>
                        </div>
                    </div>

                    {/* Scrollable Content */}
                    <div className="flex-1 overflow-y-auto pb-10">

                        {/* Summary Cards */}
                        <div className="grid grid-cols-2 gap-4 mb-8">
                            <div className="bg-black/40 p-3 rounded border border-border">
                                <p className="text-xs text-gray-500 uppercase">Duration</p>
                                <p className="text-lg font-mono text-white flex items-center gap-2">
                                    <Clock size={14} className="text-primary" />
                                    {flow.features?.flow_duration?.toFixed(4)}s
                                </p>
                            </div>
                            <div className="bg-black/40 p-3 rounded border border-border">
                                <p className="text-xs text-gray-500 uppercase">Total Packets</p>
                                <p className="text-lg font-mono text-white flex items-center gap-2">
                                    <Activity size={14} className="text-primary" />
                                    {flow.features?.total_packets}
                                </p>
                            </div>
                        </div>

                        <div className="space-y-6">
                            <div>
                                <h4 className="text-sm font-bold text-gray-400 uppercase mb-3 border-b border-border pb-1">5-Tuple Identity</h4>
                                <div className="grid grid-cols-2 gap-y-2 text-sm">
                                    <div className="text-gray-500">Source IP</div>
                                    <div className="text-white font-mono text-right">{flow.features?.src_ip}</div>

                                    <div className="text-gray-500">Source Port</div>
                                    <div className="text-white font-mono text-right">{flow.features?.src_port}</div>

                                    <div className="text-gray-500">Dest IP</div>
                                    <div className="text-white font-mono text-right">{flow.features?.dst_ip}</div>

                                    <div className="text-gray-500">Dest Port</div>
                                    <div className="text-white font-mono text-right">{flow.features?.dst_port}</div>

                                    <div className="text-gray-500">Protocol</div>
                                    <div className="text-white font-mono text-right">{getProtoName(flow.features?.protocol)}</div>

                                    {flow.features?.matched_sni_domain && flow.features?.matched_sni_domain !== 'None' && (
                                        <>
                                            <div className="text-gray-500">SNI / Domain</div>
                                            <div className="text-cyan-300 font-mono text-right break-all">{flow.features?.matched_sni_domain}</div>
                                        </>
                                    )}
                                </div>
                            </div>

                            <div>
                                <h4 className="text-sm font-bold text-gray-400 uppercase mb-3 border-b border-border pb-1">Extracted Features</h4>
                                <div className="space-y-2">
                                    {Object.entries(flow.features || {}).map(([key, value]) => {
                                        if (['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'timestamp', 'flow_duration', 'total_packets', 'verdict', 'matched_sni_domain'].includes(key)) return null;

                                        if (!value || value.toString().toLowerCase() === 'none' || value === '') return null;

                                        let displayValue = value;
                                        if (typeof value === 'object' && value !== null) {
                                            displayValue = <pre className="text-xs text-gray-400 mt-1 bg-black p-2 rounded max-h-40 overflow-auto">{JSON.stringify(value, null, 2)}</pre>;
                                        } else if (typeof value === 'boolean') {
                                            displayValue = value ? 'True' : 'False';
                                        }

                                        return (
                                            <div key={key} className="flex flex-col border-b border-border/10 pb-2 last:border-0">
                                                <span className="text-xs text-primary mb-1">{key}</span>
                                                <div className="text-sm text-gray-300 break-all font-mono">
                                                    {displayValue}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
