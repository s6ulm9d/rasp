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

export function loadConfig(partial: Partial<AgentConfig>): AgentConfig {
  const config = {
    apiKey: partial.apiKey || process.env.RASP_KEY || '',
    mode: partial.mode || (process.env.RASP_MODE as any) || 'protect',
    endpoint: partial.endpoint || process.env.RASP_URL || 'localhost:50052',
    timeout: partial.timeout || 5000
  };
  validateConfig(config);
  return config;
}