import { RuleEngine } from './engine';
import sqlRules from '../rules/sql-injection.json';
import cmdRules from '../rules/cmd-injection.json';
import pathRules from '../rules/path-traversal.json';

// In a real implementation this would load dynamically or compile into a unified set
export const defaultEngine = new RuleEngine();
defaultEngine.loadRules(sqlRules as any);
defaultEngine.loadRules(cmdRules as any);
defaultEngine.loadRules(pathRules as any);

export { RuleEngine };
export * from './types';
