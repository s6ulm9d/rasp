import { useAttackStore } from '../store/attackStore';
import { Shield, Play, Terminal, AlertTriangle, Route } from 'lucide-react';
import { useState } from 'react';

export function AttackDetail() {
  const attack = useAttackStore(state => state.selectedAttack);
  const [replayStatus, setReplayStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [replayResult, setReplayResult] = useState<string>('');

  if (!attack) {
    return (
      <div className="bg-card border border-border rounded-xl h-[600px] flex items-center justify-center text-gray-500">
        Select an attack from the stream to view details.
      </div>
    );
  }

  const handleReplay = async () => {
    setReplayStatus('loading');
    try {
      // Reconstitute Replay via GET/POST proxy if applicable or straight fetch
      const opts: RequestInit = {
        method: attack.method || 'GET',
        headers: { 'Content-Type': 'application/json' },
      };
      
      // If it's a POST, we'll try to embed the payload in the body (highly naive replay)
      if (attack.method === 'POST') {
        try {
            // Attempt to restore raw payload if it was JSON
            opts.body = attack.payload;
        } catch {
            opts.body = JSON.stringify({ payload: attack.payload });
        }
      }
      
      const res = await fetch(`http://localhost:8081${attack.path}`, opts);
      const data = await res.text();
      setReplayResult(`HTTP ${res.status}: ${data.substring(0, 100)}...`);
      setReplayStatus(res.status === 403 ? 'success' : 'error');
    } catch (e: any) {
      setReplayResult(`Fetch failed: ${e.message}`);
      setReplayStatus('error');
    }
  };

  return (
    <div className="bg-card border border-border rounded-xl flex flex-col h-[600px] overflow-hidden">
      <div className="p-4 border-b border-border flex justify-between items-center bg-[#151d2f]">
        <h2 className="font-semibold flex items-center gap-2">
          <Terminal className="w-4 h-4 text-gray-400" />
          Trace Snapshot
        </h2>
        <button 
            onClick={handleReplay}
            disabled={replayStatus === 'loading'}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50"
        >
            <Play className="w-3 h-3 fill-current" />
            Replay Attack
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        
        {/* Replay Banner */}
        {replayStatus !== 'idle' && (
          <div className={`p-3 rounded-md text-sm ${replayStatus === 'success' ? 'bg-green-500/10 text-green-400 border border-green-500/20' : replayStatus === 'error' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-blue-500/10 text-blue-400'}`}>
            <span className="font-bold">Replay Result:</span> {replayResult}
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <DetailBlock label="Attack Vector" value={attack.attackType} />
          <DetailBlock label="Risk Score" value={String(attack.score)} highlight={attack.score > 80} />
          <DetailBlock label="Target Path" value={attack.path} />
          <DetailBlock label="Request ID" value={attack.requestId || 'N/A'} />
        </div>

        <div>
          <h3 className="text-gray-400 text-xs uppercase font-bold tracking-wider mb-2 flex items-center gap-2">
            <AlertTriangle className="w-3 h-3" /> Raw Payload
          </h3>
          <div className="bg-[#0b0f19] p-3 rounded-lg border border-[#1f2937] font-mono text-sm text-red-400 break-words whitespace-pre-wrap">
            {attack.payload}
          </div>
        </div>

        {attack.normalizationLog && attack.normalizationLog.length > 0 && (
          <div>
            <h3 className="text-gray-400 text-xs uppercase font-bold tracking-wider mb-2 flex items-center gap-2">
              <Shield className="w-3 h-3 text-blue-400" /> Normalization Layers
            </h3>
            <div className="bg-[#0b0f19] p-3 rounded-lg border border-[#1f2937] space-y-1">
                {attack.normalizationLog.map((log: string, i: number) => (
                    <div key={i} className="text-xs font-mono py-1 border-b border-border/30 last:border-0">
                        <span className="text-blue-400 mr-2">➜</span> {log}
                    </div>
                ))}
            </div>
          </div>
        )}

        {attack.behavioralChain && attack.behavioralChain.length > 0 && (
          <div>
            <h3 className="text-gray-400 text-xs uppercase font-bold tracking-wider mb-2 flex items-center gap-2">
              <Route className="w-3 h-3 text-purple-400" /> IP Behavioral History
            </h3>
            <div className="flex flex-wrap gap-2">
                {attack.behavioralChain.map((event: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-purple-500/10 border border-purple-500/20 rounded text-[10px] text-purple-300 uppercase font-bold">
                        {event}
                    </span>
                ))}
            </div>
          </div>
        )}

        {attack.chain && attack.chain.length > 0 && (
          <div>
            <h3 className="text-gray-400 text-xs uppercase font-bold tracking-wider mb-2 flex items-center gap-2">
              <Terminal className="w-3 h-3 text-yellow-400" /> Sink Multi-Trigger Chain
            </h3>
            <div className="space-y-2">
                {attack.chain.map((c: any, i: number) => (
                    <div key={i} className="bg-[#0b0f19] p-3 rounded-lg border border-[#1f2937] text-sm">
                        <div className="flex justify-between mb-1">
                            <span className="font-mono text-blue-300 text-xs">{c.sink}</span>
                            <span className="text-xs text-yellow-500 font-bold">+{c.score}</span>
                        </div>
                        <div className="text-gray-400 text-xs truncate font-mono">{c.payload}</div>
                    </div>
                ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailBlock({ label, value, highlight }: { label: string, value: string, highlight?: boolean }) {
  return (
    <div>
      <div className="text-gray-500 text-xs mb-1">{label}</div>
      <div className={`font-mono text-sm ${highlight ? 'text-red-400 font-bold' : 'text-gray-200'}`}>
        {value}
      </div>
    </div>
  );
}
