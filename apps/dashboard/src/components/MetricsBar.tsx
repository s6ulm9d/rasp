import { useAttackStore } from '../store/attackStore';
import { ShieldAlert, Activity, ShieldBan, Shield } from 'lucide-react';

export function MetricsBar() {
  const attacks = useAttackStore(state => state.attacks);
  
  const total = attacks.length;
  const blocked = attacks.filter(a => a.action === 'blocked').length;
  
  const typeMap = attacks.reduce((acc, curr) => {
    acc[curr.attackType] = (acc[curr.attackType] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const topType = Object.keys(typeMap).sort((a,b) => typeMap[b] - (typeMap[a] || 0))[0] || 'None';
  
  const avgScore = total > 0 ? Math.round(attacks.reduce((sum, a) => sum + (a.score || 0), 0) / total) : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      <MetricCard 
        title="Total Attacks" 
        value={total} 
        icon={<Activity className="w-5 h-5 text-blue-400" />} 
        subtext="Captured telemetry"
      />
      <MetricCard 
        title="Blocked" 
        value={blocked} 
        icon={<ShieldBan className="w-5 h-5 text-red-500 animate-pulse" />} 
        subtext={`${total > 0 ? Math.round((blocked / total) * 100) : 0}% block rate`}
      />
      <MetricCard 
        title="Top Vector" 
        value={topType} 
        icon={<ShieldAlert className="w-5 h-5 text-orange-400" />} 
        subtext="Dominant threat"
      />
      <MetricCard 
        title="Avg Risk" 
        value={avgScore} 
        icon={<Shield className="w-5 h-5 text-purple-400" />} 
        subtext="Surface vulnerability"
      />
    </div>
  );
}

function MetricCard({ title, value, icon, subtext }: { title: string, value: string | number, icon: React.ReactNode, subtext: string }) {
  return (
    <div className="bg-card/50 backdrop-blur-sm border border-border/50 p-5 rounded-xl cyber-border hover:siem-glow transition-all duration-300 group">
      <div className="flex justify-between items-start mb-4">
        <div className="space-y-1">
          <h3 className="text-gray-500 text-[10px] uppercase font-bold tracking-widest">{title}</h3>
          <div className="text-3xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent group-hover:from-blue-400 group-hover:to-white transition-all">
            {value}
          </div>
        </div>
        <div className="p-2 bg-gray-800/30 rounded-lg border border-border/20">
          {icon}
        </div>
      </div>
      <div>
        <p className="text-[10px] text-gray-500 font-mono">{subtext}</p>
      </div>
    </div>
  );
}
