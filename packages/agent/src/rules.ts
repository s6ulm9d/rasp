export interface Rule {
    id: string;
    name: string;
    type: string;
    pattern: string;
    enabled: boolean;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description?: string;
}

export class RuleEngine {
    private rules: Rule[] = [];
    private compiledPatterns: Map<string, RegExp> = new Map();

    constructor() {
        this.loadDefaultRules();
    }

    loadRules(newRules: Rule[]) {
        this.rules.push(...newRules);
        for (const rule of newRules) {
            if (rule.pattern) {
                this.compiledPatterns.set(rule.id, new RegExp(rule.pattern, 'i'));
            }
        }
    }

    private loadDefaultRules() {
        const defaults: Rule[] = [
            {
                id: 'sqli-001',
                name: 'SQL Injection Pattern',
                type: 'sqli',
                pattern: "UNION\\s+SELECT|SLEEP\\s*\\(\\d+\\)|OR\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1['\"]?|--|#",
                enabled: true,
                severity: 'high'
            },
            {
                id: 'cmd-001',
                name: 'Shell Metachars',
                type: 'cmd_injection',
                pattern: "[;|`$><\\n\\\\&]|\\$\\s*\\(",
                enabled: true,
                severity: 'critical'
            }
        ];
        this.loadRules(defaults);
    }

    evaluate(type: string, payload: string): Rule | null {
        const relevantRules = this.rules.filter(r => r.type === type && r.enabled);
        for (const rule of relevantRules) {
            const pattern = this.compiledPatterns.get(rule.id);
            if (pattern && pattern.test(payload)) {
                return rule;
            }
        }
        return null;
    }
}

export const engine = new RuleEngine();
