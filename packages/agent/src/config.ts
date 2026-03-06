import * as fs from 'fs';
import * as path from 'path';

export interface AgentConfig {
  apiKey: string;
  mode: 'monitor' | 'alert' | 'block';
  endpoint: string;
  timeout: number;
  protections: {
    sqli: boolean;
    cmd_injection: boolean;
    xss: boolean;
    ssrf: boolean;
    path_traversal: boolean;
    prototype_pollution: boolean;
    file_inclusion: boolean;
    rce: boolean;
    deserialization: boolean;
  };
}

const DEFAULT_PROTECTIONS = {
  sqli: true,
  cmd_injection: true,
  xss: true,
  ssrf: true,
  path_traversal: true,
  prototype_pollution: true,
  file_inclusion: true,
  rce: true,
  deserialization: true
};

export function validateConfig(config: AgentConfig) {
  if (!config.apiKey && config.mode !== 'monitor') {
    console.warn('[ShieldRASP] Warning: apiKey not set. Running with default demo key.');
    config.apiKey = 'demo_agent_key_12345';
  }
}

export function loadConfig(partial: Partial<AgentConfig> = {}): AgentConfig {
  const rootDir = process.cwd();
  const configFilePath = path.join(rootDir, 'shieldrasp.json');
  let fileConfig: any = {};

  if (fs.existsSync(configFilePath)) {
    try {
      fileConfig = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
      console.log(`[ShieldRASP] Loaded configuration from ${configFilePath}`);
    } catch (e) {
      console.error(`[ShieldRASP] Error reading config file: ${e}`);
    }
  }

  const config: AgentConfig = {
    apiKey: partial.apiKey || fileConfig.apiKey || process.env.RASP_KEY || 'demo_agent_key_12345',
    mode: partial.mode || fileConfig.mode || (process.env.RASP_MODE as any) || 'block',
    endpoint: partial.endpoint || fileConfig.endpoint || process.env.RASP_URL || 'localhost:50052',
    timeout: partial.timeout || fileConfig.timeout || 5000,
    protections: {
      ...DEFAULT_PROTECTIONS,
      ...fileConfig.protections,
      ...partial.protections
    }
  };

  validateConfig(config);
  return config;
}
