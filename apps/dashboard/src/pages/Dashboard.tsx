import { useWebSocket } from '../hooks/useWebSocket';
import { MetricsBar } from '../components/MetricsBar';
import { LiveGraph } from '../components/LiveGraph';
import { AttackTable } from '../components/AttackTable';
import { AttackDetail } from '../components/AttackDetail';
import { Shield } from 'lucide-react';

export function Dashboard() {
  const { isConnected } = useWebSocket('ws://localhost:50052');

  return (
    <div className="min-h-screen p-6">
      <header className="flex justify-between items-center mb-8">
        <div className="flex items-center gap-3">
          <div className="bg-blue-600 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">ShieldRASP Command Center</h1>
            <p className="text-sm text-gray-400">Runtime Application Security Protection</p>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 bg-card border border-border px-3 py-1.5 rounded-full shadow-sm">
            <span className="relative flex h-3 w-3">
              {isConnected ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </>
              ) : (
                <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
              )}
            </span>
            <span className="text-sm font-medium text-gray-300">
              {isConnected ? 'LIVE INTERCEPT' : 'DISCONNECTED'}
            </span>
          </div>
        </div>
      </header>

      <MetricsBar />
      <LiveGraph />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AttackTable />
        </div>
        <div className="lg:col-span-1">
          <AttackDetail />
        </div>
      </div>
    </div>
  );
}
