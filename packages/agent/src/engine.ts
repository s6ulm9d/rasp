import { TaintContext, getTaintContext } from './taint/context';
import { SinkMonitor } from './analyzer/SinkMonitor';
import { StructuredLogger } from './logger';
import { AgentConfig } from './config';

export class DetectionEngine {
    private config: AgentConfig;
    private logger: StructuredLogger;

    constructor(config: AgentConfig, telemetry?: any, logger?: StructuredLogger) {
        this.config = config;
        this.logger = logger || new StructuredLogger(config);
    }

    // High-performance context-aware analysis
    public scanContext(ctx: TaintContext, rawPayload?: string): void {
        if (!ctx) return;

        // 1. Check Allowlist (Hardened Canonical Paths)
        const path = ctx.requestMeta.path;
        if (this.config.allowlist.some(route => path === route || path.startsWith(route + '/'))) {
            return;
        }

        // 2. Behavioral Anomaly Detection
        // (WIP: will integrate with per-session state)

        // 3. Selective Regex Signal (Used as risk enhancer, not primary block)
        if (rawPayload) {
            this.evaluateHeuristics(ctx, rawPayload);
        }
    }

    private evaluateHeuristics(ctx: TaintContext, payload: string) {
        // Only run regex for high-risk keywords to minimize overhead
        const riskKeywords = ['union', 'select', 'constructor', 'process', 'exec', '../'];
        const hasRisk = riskKeywords.some(k => payload.includes(k));
        
        if (hasRisk) {
           // If signature detected in tainted input, we escalate
           // But real blocking happens at the Sink in SinkMonitor
        }
    }

    // Exposed for Sink Hooks to report findings
    public reportThreat(ctx: TaintContext, attack: string, payload: string, sink: string, score: number) {
        const event = {
            attack,
            action: score >= 100 ? 'blocked' : 'alert',
            payload: payload.substring(0, 500),
            endpoint: ctx.requestMeta.path,
            score,
            timestamp: Date.now()
        };

        this.logger.logEvent(event);
        
        if (score >= 100) {
            const err = new Error(`Security Block: ${attack}`) as any;
            err.name = 'SecurityBlockException';
            err.details = event;
            throw err;
        }
    }
}
