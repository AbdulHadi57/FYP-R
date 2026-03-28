import React from 'react';

export default function KPIWidget({ title, value, subtext, icon: Icon, color }) {
    const getColorClasses = (c) => {
        switch (c) {
            case 'red': return 'bg-danger text-danger border-danger/30';
            case 'green': return 'bg-success text-success border-success/30';
            case 'blue': return 'bg-primary text-primary border-primary/30';
            default: return 'bg-primary text-primary border-primary/30';
        }
    };

    const colorClass = getColorClasses(color);

    return (
        <div className="bg-surface border border-border rounded-lg p-4 shadow-lg hover:border-primary transition-colors duration-300">
            <div className="flex justify-between items-start">
                <div>
                    <p className="text-gray-500 text-sm uppercase tracking-wider font-semibold">{title}</p>
                    <h3 className="text-3xl font-bold text-white mt-2 font-mono">{value}</h3>
                    <p className={`text-sm mt-1 font-medium ${color === 'red' ? 'text-danger' :
                            color === 'yellow' ? 'text-yellow-400' :
                                color === 'blue' ? 'text-blue-400' :
                                    'text-success'
                        }`}>
                        {subtext}
                    </p>
                </div>
                <div className={`p-3 rounded-lg bg-opacity-10 border bg-surface ${color === 'red' ? 'text-danger border-danger/20' :
                        color === 'yellow' ? 'text-yellow-400 border-yellow-400/20' :
                            color === 'blue' ? 'text-blue-400 border-blue-400/20' :
                                'text-success border-success/20'
                    }`}>
                    <Icon size={24} />
                </div>
            </div>
        </div>
    );
}
