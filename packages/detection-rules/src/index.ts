import { RuleEngine } from './engine';
import { Rule } from './types';
import * as sqlRules from '../rules/sql-injection.json';
import * as cmdRules from '../rules/cmd-injection.json';
import * as pathRules from '../rules/path-traversal.json';

const engine = new RuleEngine();
engine.loadRules(sqlRules as unknown as Rule[]);
engine.loadRules(cmdRules as unknown as Rule[]);
engine.loadRules(pathRules as unknown as Rule[]);

export { engine, RuleEngine };
export * from './types';
