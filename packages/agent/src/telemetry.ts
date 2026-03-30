import * as fs from 'fs';
import * as path from 'path';
import { io, Socket } from 'socket.io-client';
import { AgentConfig } from './config';

export interface SecurityEvent {
    type: 'detect';
    attack: string;
    confidence: number;
    payload: string;
    blocked: boolean;
    timestamp: string;
    method?: string;
    path?: string;
    ip?: string;
}

export class TelemetryClient {
    private socket: Socket;
    private logPath: string;

    constructor(private config: AgentConfig) {
        this.socket = io(this.config.endpoint, { reconnection: true });
        this.logPath = path.join(this.config.logDir, 'agent.log');

        this.socket.on('connect', () => {
            console.log(`[ShieldRASP] Telemetry connected to ${this.config.endpoint}`);
        });
    }

    public report(event: Partial<SecurityEvent>) {
        const fullEvent: SecurityEvent = {
            type: 'detect',
            attack: event.attack || 'Unknown',
            confidence: event.confidence || 0.99,
            payload: event.payload || '',
            blocked: event.blocked ?? (this.config.mode === 'block'),
            timestamp: new Date().toISOString(),
            method: event.method,
            path: event.path,
            ip: event.ip
        };

        // 1. Log to console
        const color = fullEvent.blocked ? '\x1b[31m' : '\x1b[33m';
        const action = fullEvent.blocked ? 'BLOCKED' : 'ALERTED';
        console.error(`${color}[ShieldRASP] ATTACK DETECTED: ${fullEvent.attack} | Action: ${action} | Path: ${fullEvent.path}\x1b[0m`);

        // 2. Log to local file
        try {
            fs.appendFileSync(this.logPath, JSON.stringify(fullEvent) + '\n');
        } catch (e) {
            console.error(`[ShieldRASP] Failed to write to local log: ${e}`);
        }

        // 3. Stream to monitor
        if (this.socket.connected) {
            this.socket.emit('telemetry', fullEvent);
        }
    }
}
