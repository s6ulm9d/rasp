import { Rule } from './types';

export class RuleEngine {
    private rules: Rule[] = [];
    private compiledPatterns: Map<string, RegExp> = new Map();

    loadRules(newRules: Rule[]) {
        this.rules.push(...newRules);
        for (const rule of newRules) {
            if (rule.pattern) {
                this.compiledPatterns.set(rule.id, new RegExp(rule.pattern, 'i'));
            }
        }
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
