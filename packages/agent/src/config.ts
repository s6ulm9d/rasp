import * as fs from 'fs';
import * as path from 'path';

export interface AgentConfig {
  mode: 'block' | 'alert';
  endpoint: string;
  logDir: string;
  protections: {
    sqli: boolean;
    nosql: boolean;
    cmd: boolean;
    rce: boolean;
    path: boolean;
    prototype: boolean;
    ssrf: boolean;
  };
  thresholds: {
    block: number;
    log: number;
  };
  policies?: Record<string, 'block' | 'alert' | 'off'>;
  sensitivity: 'high' | 'medium' | 'low';
  allowlist: string[];
}

const DEFAULT_CONFIG: AgentConfig = {
  mode: 'block',
  endpoint: 'http://localhost:50052',
  logDir: path.join(process.env.HOME || process.env.USERPROFILE || '.', '.shieldrasp', 'logs'),
  protections: {
    sqli: true,
    nosql: true,
    cmd: true,
    rce: true,
    path: true,
    prototype: true,
    ssrf: true
  },
  thresholds: {
    block: 80,
    log: 50
  },
  sensitivity: 'high',
  allowlist: []
};

export function loadConfig(): AgentConfig {
  const configPath = path.join(process.cwd(), 'shieldrasp.json');
  let config = { ...DEFAULT_CONFIG };

  if (fs.existsSync(configPath)) {
    try {
      const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      config = { ...config, ...fileConfig };
      config.protections = { ...DEFAULT_CONFIG.protections, ...fileConfig.protections };
      config.thresholds = { ...DEFAULT_CONFIG.thresholds, ...fileConfig.thresholds };

      // Migrate boolean protections to modern Policy configurations
      config.policies = {};
      for (const [key, val] of Object.entries(config.protections)) {
        if (typeof val === 'boolean') {
          config.policies[key] = val ? config.mode : 'off';
        } else if (typeof val === 'string' && ['block', 'alert', 'off'].includes(val)) {
          config.policies[key] = val as any;
        }
      }

      if (fileConfig.policies) {
        config.policies = { ...config.policies, ...fileConfig.policies };
      }

    } catch (e) {
      console.error(`[ShieldRASP] Failed to parse shieldrasp.json, using defaults.`);
    }
  }

  // Initialize defaults if not overridden
  if (!config.policies) {
    config.policies = {};
    for (const [key, val] of Object.entries(config.protections)) {
      config.policies[key] = val ? config.mode : 'off';
    }
  }

  // Ensure log directory exists
  if (!fs.existsSync(config.logDir)) {
    fs.mkdirSync(config.logDir, { recursive: true });
  }

  return config;
}
