import { useMemo } from 'react';
import { useAttackStore } from '../store/attackStore';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export function LiveGraph() {
  const attacks = useAttackStore(state => state.attacks);

  const data = useMemo(() => {
    // Generate buckets for the last 60 seconds
    const now = Date.now();
    const buckets: Record<string, number> = {};
    
    // Initialize exactly 60 buckets back in time
    for (let i = 59; i >= 0; i--) {
        const time = new Date(now - i * 1000).toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
        buckets[time] = 0;
    }

    attacks.forEach(a => {
        if (now - a.timestamp <= 60000) {
            const time = new Date(a.timestamp).toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
            if (buckets[time] !== undefined) buckets[time]++;
        }
    });

    return Object.keys(buckets).map(time => ({
        time,
        Attacks: buckets[time]
    }));
  }, [attacks]);

  return (
    <div className="bg-card border border-border p-5 rounded-xl mb-6 h-[250px] shadow-sm flex flex-col">
        <h3 className="text-gray-400 text-sm font-medium mb-4">Attacks / Second (Last 60s)</h3>
        <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                    <XAxis 
                        dataKey="time" 
                        stroke="#4b5563" 
                        fontSize={10} 
                        tick={{ fill: '#4b5563' }}
                        tickMargin={10}
                        minTickGap={20}
                    />
                    <YAxis 
                        stroke="#4b5563" 
                        fontSize={10} 
                        tick={{ fill: '#4b5563' }}
                        allowDecimals={false}
                    />
                    <Tooltip 
                        contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#f3f4f6' }}
                        itemStyle={{ color: '#ef4444' }}
                        cursor={{ stroke: '#374151' }}
                    />
                    <Line 
                        type="monotone" 
                        dataKey="Attacks" 
                        stroke="#ef4444" 
                        strokeWidth={2}
                        dot={false}
                        isAnimationActive={false}
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    </div>
  );
}
