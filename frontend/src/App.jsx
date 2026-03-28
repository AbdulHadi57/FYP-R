import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, LayoutDashboard, Database, Fingerprint, ShieldAlert, SlidersHorizontal, GitBranch, FileText } from 'lucide-react';

import ThreatOverview from './tabs/ThreatOverview';
import JA4Module from './tabs/modules/JA4Module';
import APTModule from './tabs/modules/APTModule';
import RawData from './tabs/RawData';
import ControlPlaneTab from './tabs/ControlPlaneTab';
import DetectionPipeline from './tabs/DetectionPipeline';
import AuditTrailTab from './tabs/AuditTrailTab';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedFlowId, setSelectedFlowId] = useState(null);

  const handleNavigateToFlow = (flowId) => {
    setSelectedFlowId(flowId);
    setActiveTab('raw');
  };

  const [status, setStatus] = useState('offline');

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await axios.get('/api/stats');
        const data = res.data;

        if (data.last_flow_timestamp) {
          const lastTime = new Date(data.last_flow_timestamp).getTime();
          const now = Date.now();
          if (now - lastTime < 15000) {
            setStatus('online');
          } else {
            setStatus('offline');
          }
        } else {
          setStatus('offline');
        }
      } catch (e) {
        setStatus('offline');
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const renderTab = () => {
    switch (activeTab) {
      case 'overview': return <ThreatOverview />;
      case 'pipeline': return <DetectionPipeline />;
      case 'ja4': return <JA4Module onNavigateFlow={handleNavigateToFlow} />;
      case 'apt': return <APTModule />;
      case 'audit': return <AuditTrailTab />;
      case 'control': return <ControlPlaneTab />;
      case 'raw': return <RawData selectedFlowId={selectedFlowId} />;
      default: return <ThreatOverview />;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Threat Overview', icon: LayoutDashboard },
    { id: 'pipeline', label: 'Detection Pipeline', icon: GitBranch },
    { id: 'control', label: 'Control Plane', icon: SlidersHorizontal },
    { id: 'audit', label: 'Audit Trail', icon: FileText },
    { id: 'ja4', label: 'JA4 Fingerprinting', icon: Fingerprint },
    { id: 'apt', label: 'APT Detection', icon: ShieldAlert },
    { id: 'raw', label: 'Raw Data Inspector', icon: Database },
  ];

  return (
    <div className="min-h-screen bg-background text-gray-300 font-sans selection:bg-primary selection:text-black">
      {/* Unified Header & Nav */}
      <header className="bg-black/30 backdrop-blur-md border-b border-white/10 sticky top-0 z-50 transition-all duration-300">
        <div className="container mx-auto p-4 flex flex-col md:flex-row items-center justify-between gap-4">

          {/* Brand & Status */}
          <div className="flex items-center gap-4 self-start md:self-auto">
            <div className={`z-10 relative transition-all duration-500 ${status === 'online' ? 'logo-glow-intense' : ''}`}>
              <Shield className={`w-10 h-10 transition-colors duration-500 ${status === 'online' ? 'text-cyan-400' : 'text-gray-600'}`} />
            </div>
            <h1 className={`text-3xl font-bold tracking-wider transition-all duration-500 ${status === 'online'
                ? 'bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-blue-400 to-cyan-400'
                : 'text-gray-600'
              }`}
              style={{ textShadow: status === 'online' ? "0 0 20px rgba(6,182,212,0.5)" : "none" }}
            >
              AEGISNET
            </h1>
          </div>

          {/* Navigation Pills */}
          <nav className="flex items-center gap-2 overflow-x-auto w-full md:w-auto pb-1 md:pb-0 scrollbar-hide">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all duration-300 whitespace-nowrap border
                    ${isActive
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                      : 'bg-transparent text-gray-400 border-transparent hover:bg-white/5 hover:text-gray-200 hover:border-white/10'
                    }
                  `}
                >
                  <Icon size={16} className={isActive ? 'animate-pulse' : ''} />
                  {tab.label}
                </button>
              );
            })}
          </nav>

        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {renderTab()}
      </main>
    </div>
  );
}

export default App;
