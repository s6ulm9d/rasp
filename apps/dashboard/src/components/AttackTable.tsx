import { useAttackStore } from '../store/attackStore';
import { motion, AnimatePresence } from 'framer-motion';
import clsx from 'clsx';
import { Search } from 'lucide-react';
import { useState } from 'react';

export function AttackTable() {
  const attacks = useAttackStore((state) => state.attacks);
  const setSelectedAttack = useAttackStore((state) => state.setSelectedAttack);
  const selectedAttack = useAttackStore((state) => state.selectedAttack);
  
  const [filter, setFilter] = useState('');

  const filtered = attacks.filter(a => 
    a.attackType.toLowerCase().includes(filter.toLowerCase()) || 
    a.path.toLowerCase().includes(filter.toLowerCase()) ||
    a.payload.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="bg-card border border-border rounded-xl flex flex-col overflow-hidden h-[600px]">
      <div className="p-4 border-b border-border flex justify-between items-center bg-[#151d2f]">
        <h2 className="font-semibold text-gray-200">Alert Stream</h2>
        <div className="relative">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input 
            type="text" 
            placeholder="Search payload, type, path..." 
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-[#0b0f19] border border-border text-sm text-gray-300 rounded-md py-1.5 pl-9 pr-3 outline-none focus:border-blue-500 w-64"
          />
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-left text-sm whitespace-nowrap">
          <thead className="bg-[#111827] sticky top-0 z-10 border-b border-border text-gray-400">
            <tr>
              <th className="font-medium p-4 w-32">Time</th>
              <th className="font-medium p-4 w-24">Score</th>
              <th className="font-medium p-4 w-40">Type</th>
              <th className="font-medium p-4">Path</th>
              <th className="font-medium p-4 w-24">Action</th>
            </tr>
          </thead>
          <tbody className="bg-[#111827]">
            <AnimatePresence>
              {filtered.map((attack) => (
                <motion.tr 
                  key={`${attack.timestamp}-${attack.requestId || Math.random()}`}
                  initial={{ opacity: 0, backgroundColor: 'rgba(239, 68, 68, 0.2)' }}
                  animate={{ opacity: 1, backgroundColor: attack === selectedAttack ? 'rgba(30, 58, 138, 0.3)' : 'transparent' }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3 }}
                  onClick={() => setSelectedAttack(attack)}
                  className="border-b border-border/50 cursor-pointer hover:bg-white/5 transition-colors"
                >
                  <td className="p-4 text-gray-400">
                    {new Date(attack.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-4">
                    <span className={clsx(
                      "px-2 py-0.5 rounded text-xs font-bold",
                      attack.score > 100 ? "bg-red-500/20 text-red-400" :
                      attack.score >= 70 ? "bg-orange-500/20 text-orange-400" :
                      "bg-yellow-500/20 text-yellow-400"
                    )}>
                      {attack.score}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-xs text-blue-300">
                    {attack.attackType}
                  </td>
                  <td className="p-4 text-gray-300 max-w-[200px] truncate">
                    {attack.path}
                  </td>
                  <td className="p-4">
                    <span className={clsx(
                      "px-2 py-1 rounded-md text-xs font-medium",
                      attack.action === 'blocked' ? "bg-red-500/10 text-red-500 border border-red-500/20" : "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20"
                    )}>
                      {attack.action.toUpperCase()}
                    </span>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="p-8 text-center text-gray-500">
            No attacks matching filters, or waiting for traffic...
          </div>
        )}
      </div>
    </div>
  );
}
