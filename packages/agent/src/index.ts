import { loadConfig } from './config';
import { TelemetryClient } from './telemetry';
import { StructuredLogger } from './logger';
import { DetectionEngine } from './engine';
import { setupInboundHook } from './hooks/inbound';
import { setupSqlHooks } from './hooks/sql';
import { setupNoSqlHooks } from './hooks/nosql';
import { setupCmdHooks } from './hooks/cmd';
import { setupPathHooks } from './hooks/path';
import { setupRceHooks } from './hooks/rce';
import { setupPrototypeHooks } from './hooks/prototype';
import { setupSsrfHooks } from './hooks/ssrf';
import { setupNetHooks } from './hooks/net';

export class ShieldRASPAgent {
    private static instance: ShieldRASPAgent;
    private isStarted: boolean = false;

    private constructor() { }

    public static getInstance(): ShieldRASPAgent {
        if (!ShieldRASPAgent.instance) {
            ShieldRASPAgent.instance = new ShieldRASPAgent();
        }
        return ShieldRASPAgent.instance;
    }

    public start() {
        if (this.isStarted) return;

        const config = loadConfig();
        const telemetry = new TelemetryClient(config);
        const logger = new StructuredLogger(config);
        const engine = new DetectionEngine(config, telemetry, logger);

        console.log(`[ShieldRASP] Current Mode: ${config.mode.toUpperCase()}`);

        // Initialize all security hooks with the Deterministic Decision Engine
        setupInboundHook(config, telemetry); // Inbound doesn't trigger alerts, just sets taint context
        setupSqlHooks(engine);
        setupNoSqlHooks(engine);
        setupCmdHooks(engine);
        setupPathHooks(engine);
        setupRceHooks(engine);
        setupPrototypeHooks(engine);
        setupSsrfHooks(engine);
        setupNetHooks(engine);

        this.isStarted = true;
    }
}


// Automatic initialization for NODE_OPTIONS="--require @shieldrasp/agent"
const agent = ShieldRASPAgent.getInstance();
agent.start();

export const start = () => agent.start();
export default agent;
