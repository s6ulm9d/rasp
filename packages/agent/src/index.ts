import { AgentConfig, loadConfig } from './config';
import { TelemetryClient } from './telemetry/client';
import { hookFs } from './hooks/fs';
import { hookHttp } from './hooks/http';
import { hookChildProcess } from './hooks/cp';
import { hookPg } from './hooks/pg';
import { hookInbound } from './hooks/inbound';
import { hookDynamicExc } from './hooks/dynamic';
import { hookMysql } from './hooks/mysql';
import { hookMongo } from './hooks/mongodb';

export class ShieldRASPAgent {
    private static instance: ShieldRASPAgent;
    private config!: AgentConfig;
    private telemetry!: TelemetryClient;
    private isStarted: boolean = false;

    private constructor() { }

    public static getInstance(): ShieldRASPAgent {
        if (!ShieldRASPAgent.instance) {
            ShieldRASPAgent.instance = new ShieldRASPAgent();
        }
        return ShieldRASPAgent.instance;
    }

    /**
     * Start the RASP protection agent.
     */
    public start(partialConfig: Partial<AgentConfig> = {}) {
        if (this.isStarted) return this;

        this.config = loadConfig(partialConfig);
        this.telemetry = new TelemetryClient(this.config);

        console.log(`[ShieldRASP] Current Mode: ${this.config.mode.toUpperCase()}`);

        // Register core instrumentation hooks
        hookInbound(this.config, this.telemetry); // Ingress & Taint Propagation
        hookFs(this.config, this.telemetry);      // Filesystem Security (Traversal)
        hookHttp(this.config, this.telemetry);    // Network requests (SSRF)
        hookChildProcess(this.config, this.telemetry); // Command injection
        hookPg(this.config, this.telemetry);      // PostgreSQL queries
        hookMysql(this.config, this.telemetry);   // MySQL queries
        hookMongo(this.config, this.telemetry);   // MongoDB queries
        hookDynamicExc(this.config, this.telemetry); // eval / vm / Function (RCE)

        this.isStarted = true;
        return this;
    }

    /** @deprecated Use start() instead */
    public init(config: Partial<AgentConfig> = {}) {
        return this.start(config);
    }
}

// Singleton export functions
export const start = (config: Partial<AgentConfig> = {}) => {
    return ShieldRASPAgent.getInstance().start(config);
};

export const init = (config: Partial<AgentConfig> = {}) => {
    return ShieldRASPAgent.getInstance().init(config);
};

// Automatic initialization for NODE_OPTIONS="--require @shieldrasp/agent"
// We check if this is being required and not just imported as part of a bundle.
if (process.env.RASP_AUTO_LOAD !== 'false' && (process.env.NODE_OPTIONS?.includes('--require @shieldrasp/agent') || process.env.NODE_OPTIONS?.includes('--require ./packages/agent'))) {
    start();
}

export { RASPBlockError } from './errors';

