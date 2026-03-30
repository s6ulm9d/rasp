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

        try {
            fs.appendFileSync(this.logFile, JSON.stringify(payload) + '\n', 'utf8');
        } catch (e) {
            // Fail silently if we can't write to log to avoid disrupting the app
            console.error('[ShieldRASP] File logging failed:', e);
        }
    }
}
