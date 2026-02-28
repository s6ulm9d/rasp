import { Rule } from './types';

export class RuleEngine {
    private rules: Rule[] = [];
    private compiledPatterns: Map<string, RegExp> = new Map();

    loadRules(newRules: Rule[]) {
        this.rules.push(...newRules);
        for (const rule of newRules) {
            if (rule.pattern) {
                this.compiledPatterns.set(rule.id, new RegExp(rule.pattern));
            }
        }
    }

    evaluate(input: string, context: string, isTainted: boolean) {
        const matches: Rule[] = [];
        for (const rule of this.rules) {
            if (rule.context !== context) continue;
            if (rule.taint_required && !isTainted) continue;

            const regex = this.compiledPatterns.get(rule.id);
            if (regex && regex.test(input)) {
                matches.push(rule);
            }
        }
        return matches;
    }
}
