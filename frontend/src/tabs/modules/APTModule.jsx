import React from 'react';
import { ShieldAlert, Info } from 'lucide-react';

export default function APTModule() {
    return (
        <div className="flex flex-col items-center justify-center h-[600px] border border-dashed border-gray-700 rounded-lg bg-surface/30">
            <div className="p-6 bg-primary/10 rounded-full mb-6">
                <ShieldAlert size={64} className="text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white mb-2">APT Module Not Configured</h2>
            <p className="text-gray-400 max-w-md text-center">
                The Advanced Persistent Threat (APT) detection module is currently disabled or waiting for configuration updates.
            </p>
            <div className="mt-8 flex items-center gap-2 text-sm text-gray-500 bg-black/50 px-4 py-2 rounded">
                <Info size={16} />
                <span>Waiting for user specification...</span>
            </div>
        </div>
    );
}
