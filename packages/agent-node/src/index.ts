import { AgentConfig, loadConfig } from './config';
import { TelemetryClient } from './telemetry/client';
import { hookFs } from './hooks/fs';
import { hookHttp } from './hooks/http';
import { hookChildProcess } from './hooks/cp';
import { hookPg } from './hooks/pg';
import { hookInbound } from './hooks/inbound';

export class ShieldRASPAgent {
    private static instance: ShieldRASPAgent;
    private config!: AgentConfig;
    private telemetry!: TelemetryClient;

    private constructor() { }

    public static getInstance(): ShieldRASPAgent {
        if (!ShieldRASPAgent.instance) {
            ShieldRASPAgent.instance = new ShieldRASPAgent();
        }
        return ShieldRASPAgent.instance;
    }

    public init(partialConfig: Partial<AgentConfig> = {}) {
        this.config = loadConfig(partialConfig);
        this.telemetry = new TelemetryClient(this.config);

        console.log(`[ShieldRASP] Initializing Agent in mode: ${this.config.mode}`);

        // Register all hooks
        hookFs(this.config, this.telemetry);
        hookHttp(this.config, this.telemetry);
        hookChildProcess(this.config, this.telemetry);
        hookPg(this.config, this.telemetry);
        hookInbound(this.config, this.telemetry);

        return this;
    }
}

export const init = (config: Partial<AgentConfig> = {}) => {
    return ShieldRASPAgent.getInstance().init(config);
};

export { RASPBlockError } from './errors';
