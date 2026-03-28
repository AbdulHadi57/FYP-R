import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    Legend, ComposedChart, Line
} from 'recharts';

export default function TrafficForensics() {
    const [data, setData] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await axios.get('/api/forensics?limit=5000');
                setData(res.data);
            } catch (error) {
                console.error("Error fetching forensics data:", error);
            }
        };
        fetchData();
        const interval = setInterval(fetchData, 5000); // Auto-refresh every 5s
        return () => clearInterval(interval);
    }, []);

    if (!data) return <div className="text-white">Loading Forensics Data...</div>;

    // Process Payload Histograms
    const createHistogram = (values, bins = 20) => {
        if (!values.length) return [];
        const max = Math.max(...values, 1500); // multiple of MTU usually
        const step = max / bins;
        const histogram = Array.from({ length: bins }, (_, i) => ({
            bin: `${Math.floor(i * step)}-${Math.floor((i + 1) * step)}`,
            count: 0,
            rangeStart: i * step
        }));

        values.forEach(v => {
            const binIdx = Math.min(Math.floor(v / step), bins - 1);
            if (histogram[binIdx]) histogram[binIdx].count++;
        });
        return histogram;
    };

    const fwdHist = createHistogram(data.payload_stats.fwd);
    const bwdHist = createHistogram(data.payload_stats.bwd);

    // Combine for side-by-side
    const payloadData = fwdHist.map((h, i) => ({
        bin: h.bin,
        fwd: h.count,
        bwd: bwdHist[i]?.count || 0
    }));

    return (
        <div className="space-y-6">
            {/* TCP Flag Analysis */}
            <div className="card h-80">
                <h3 className="text-xl font-bold text-white mb-2">TCP Flag Analysis</h3>
                <p className="text-gray-400 text-sm mb-4">Distribution of TCP control flags. High SYN + Low ACK indicates scanning.</p>
                <div className="flex-1 min-h-0">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={data.flag_counts || []}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                            <XAxis dataKey="flag" stroke="#666" />
                            <YAxis stroke="#666" />
                            <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff' }} />
                            <Bar dataKey="count" fill="#ffbb28" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Payload Analysis */}
            <div className="card h-80">
                <h3 className="text-xl font-bold text-white mb-2">Payload Distribution</h3>
                <p className="text-gray-400 text-sm mb-4">Forward vs Backward payload sizes (Bytes).</p>
                <div className="flex-1 min-h-0">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={payloadData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                            <XAxis dataKey="bin" stroke="#666" tick={{ fontSize: 10 }} interval={2} />
                            <YAxis stroke="#666" />
                            <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff' }} />
                            <Legend />
                            <Bar dataKey="fwd" name="Fwd Payload" fill="#00e0ff" stackId="a" />
                            <Bar dataKey="bwd" name="Bwd Payload" fill="#ff4b4b" stackId="a" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Top Ports */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="card h-80 flex flex-col">
                    <h3 className="text-xl font-bold text-white mb-2">Targeted Ports</h3>
                    <p className="text-gray-400 text-sm mb-4">Most frequent destination ports.</p>
                    <div className="flex-1 min-h-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart layout="vertical" data={data.top_ports || []} barSize={20}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                                <XAxis type="number" stroke="#666" />
                                <YAxis dataKey="port" type="category" stroke="#fff" width={80} />
                                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff', borderRadius: '8px' }} />
                                <Bar dataKey="count" fill="#00cc96" radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="card h-80 flex flex-col">
                    <h3 className="text-xl font-bold text-white mb-2">Most Active Clients</h3>
                    <p className="text-gray-400 text-sm mb-4">Top Source IPs generating traffic.</p>
                    <div className="flex-1 min-h-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart layout="vertical" data={data.top_source_ips || []} barSize={20}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                                <XAxis type="number" stroke="#666" />
                                <YAxis dataKey="ip" type="category" stroke="#fff" width={100} tick={{ fontSize: 11 }} />
                                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#333', color: '#fff', borderRadius: '8px' }} />
                                <Bar dataKey="count" fill="#ff4b4b" radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
}
