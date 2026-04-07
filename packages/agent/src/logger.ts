import * as fs from 'fs';
import * as path from 'path';
import { AgentConfig } from './config';

export class StructuredLogger {
    private logFile: string;

    constructor(config: AgentConfig) {
        this.logFile = path.join(config.logDir, 'shieldrasp-events.json');
    }

    public logEvent(event: any) {
        const payload = {
            timestamp: new Date().toISOString(),
            ...event
        };

        const color = event.action === 'blocked' ? '\x1b[31m' : '\x1b[33m'; // Red for block, Yellow for alert
        const reset = '\x1b[0m';
        console.log(`${color}[ShieldRASP] ATTACK DETECTED: ${event.attack} | Action: ${event.action.toUpperCase()} | Path: ${event.endpoint}${reset}`);

        try {
            fs.appendFileSync(this.logFile, JSON.stringify(payload) + '\n', 'utf8');
        } catch (e) {
            console.error('[ShieldRASP] File logging failed:', e);
        }
    }
}
