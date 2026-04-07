import * as fs from 'fs';
import * as path from 'path';

export interface PolicyRule {
    action: 'block' | 'alert' | 'off';
    threshold?: number;
    sensitivity?: 'high' | 'low' | 'standard';
    allowlist?: string[];
}

export interface ShieldPolicy {
    version: string;
    mode: 'block' | 'monitor' | 'off';
    thresholds: {
        block: number;
        log: number;
    };
    rules: {
        [key: string]: PolicyRule;
    };
    globalAllowlist: string[];
}

const DEFAULT_POLICY: ShieldPolicy = {
    version: "1.0",
    mode: "monitor",
    thresholds: {
        block: 80,
        log: 40
    },
    rules: {
        sqli: { action: 'block', threshold: 80 },
        nosql: { action: 'block', threshold: 80 },
        cmd: { action: 'block', threshold: 90 },
        rce: { action: 'block', threshold: 90 },
        path: { action: 'block', threshold: 70 },
        ssrf: { action: 'block', threshold: 80 },
        prototype: { action: 'block', threshold: 80 }
    },
    globalAllowlist: ['/favicon.ico', '/health']
};

export class PolicyEngine {
    private policy: ShieldPolicy;
    private policyPath: string;

    constructor(configDir: string) {
        this.policyPath = path.join(configDir, 'shieldrasp.policy.json');
        this.policy = this.loadPolicy();
    }

    private loadPolicy(): ShieldPolicy {
        try {
            if (fs.existsSync(this.policyPath)) {
                const data = fs.readFileSync(this.policyPath, 'utf8');
                return { ...DEFAULT_POLICY, ...JSON.parse(data) };
            }
        } catch (e) {
            console.error('[ShieldRASP] Failed to load policy file, using defaults');
        }
        return DEFAULT_POLICY;
    }

    public getAction(attackType: string, score: number): 'block' | 'alert' | 'off' {
        if (this.policy.mode === 'off') return 'off';

        const rule = this.policy.rules[attackType];
        const action = rule ? rule.action : this.policy.mode === 'block' ? 'block' : 'alert';
        
        const threshold = rule?.threshold || this.policy.thresholds.block;

        if (action === 'block' && score >= threshold) {
            return 'block';
        }
        
        if (score >= this.policy.thresholds.log) {
            return 'alert';
        }

        return 'off';
    }

    public getMode(): string {
        return this.policy.mode;
    }

    public getThresholds() {
        return this.policy.thresholds;
    }

    public getAllowlist(): string[] {
        return this.policy.globalAllowlist;
    }
}
