export interface AgentConfig {
  apiKey: string;
  mode?: 'monitor' | 'protect';
  endpoint?: string;
  timeout?: number;
}

export function validateConfig(config: AgentConfig) {
  if (!config.apiKey) {
    throw new Error('[ShieldRASP] Critical Error: apiKey is required to initialize the agent.');
  }
  config.mode = config.mode || 'protect';
  config.endpoint = config.endpoint || 'localhost:50051';
  config.timeout = config.timeout || 5000;
}