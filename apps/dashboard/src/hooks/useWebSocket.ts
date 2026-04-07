import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAttackStore } from '../store/attackStore';

export function useWebSocket(url: string) {
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef<Socket | null>(null);
  const addAttack = useAttackStore((state) => state.addAttack);

  useEffect(() => {
    socketRef.current = io(url, {
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
    });

    socketRef.current.on('connect', () => {
      setIsConnected(true);
    });

    socketRef.current.on('disconnect', () => {
      setIsConnected(false);
    });

    socketRef.current.on('telemetry', (data: any) => {
      // Handle potential stringified JSON
      const event = typeof data === 'string' ? JSON.parse(data) : data;
      
      addAttack({
        requestId: event.requestId,
        type: event.type || 'detect',
        attackType: event.attack || 'Unknown',
        score: event.score || 0,
        payload: event.payload || '',
        path: event.path || '/',
        timestamp: event.timestamp ? new Date(event.timestamp).getTime() : Date.now(),
        blocked: event.blocked || event.action === 'blocked',
        action: event.action || (event.blocked ? 'blocked' : 'logged'),
        chain: event.chain,
        behavioralChain: event.behavioralChain,
        normalizationLog: event.normalizationLog,
        method: event.method,
        ip: event.ip,
      });
    });

    return () => {
      socketRef.current?.disconnect();
    };
  }, [url, addAttack]);

  return { isConnected };
}
