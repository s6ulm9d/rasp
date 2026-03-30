import { AgentConfig } from './config';
import { TelemetryClient } from './telemetry';
import { StructuredLogger } from './logger';
import { TaintContext } from './taint/context';
import { SecurityBlockException } from './errors';

export interface ThreatEvaluation {
    attack: string;
    payload: string;
    sink: string;
    baseScore: number;
    tainted: boolean;
}

export class DetectionEngine {
    private config: AgentConfig;
    private telemetry: TelemetryClient;
    private logger: StructuredLogger;

    constructor(config: AgentConfig, telemetry: TelemetryClient, logger: StructuredLogger) {
        this.config = config;
        this.telemetry = telemetry;
        this.logger = logger;
    }

    private logThrottleMap = new Map<string, number>();

    public evaluate(ctx: TaintContext, threat: ThreatEvaluation) {
        // Map sink types to their generic attack keys for policy selection
        const attackKey = threat.attack === 'SQL Injection' ? 'sqli' :
            threat.attack === 'NoSQL Injection' ? 'nosql' :
                threat.attack === 'Command Injection' ? 'cmd' :
                    threat.attack === 'Remote Code Execution' ? 'rce' :
                        threat.attack === 'Path Traversal' ? 'path' :
                            threat.attack === 'Prototype Pollution' ? 'prototype' :
                                threat.attack === 'SSRF' ? 'ssrf' : 'unknown';

        const policy = this.config.policies![attackKey] || this.config.mode;

        if (policy === 'off') return; // Policy Engine bypass

        // 1. False Positive Allowance checks
        if (this.config.allowlist.some(route => ctx.requestMeta.path.startsWith(route))) {
            return; // Allowed by exception
        }

        // 2. Risk Score calculation
        let score = threat.baseScore;

        if (threat.tainted) {
            score += 30; // Heavy penalty for proven tainted data arriving at sinks
        }

        // 2b. Entropy / Complexity Detection (Catching Heavily Obfuscated Malware Streams)
        if (threat.payload.length > 20) {
            const entropy = this.calculateEntropy(threat.payload);
            if (entropy > 0.8) {
                // Highly complex payload (Base64'd / Packed). Severe anomaly.
                score += 20;
            }
        }

        if (this.config.sensitivity === 'high') score += 10;
        if (this.config.sensitivity === 'low') score -= 10;

        // 3. Accumulate Attack Chain Context
        // Cap chain size dynamically to prevent massive array memory leaks on bloated requests
        if (ctx.triggeredRules.length >= 20) return;

        ctx.triggeredRules.push({
            attack: threat.attack,
            payload: threat.payload.substring(0, 500),
            sink: threat.sink,
            score: score,
            timestamp: Date.now()
        });

        ctx.totalScore += score;
        
        ctx.requestMeta.flow.push(threat.sink);
        
        // 5. Context Correlation Engine: Detecting Multi-Phase RCE Chains
        const flw = ctx.requestMeta.flow;
        const hasInput = flw.includes('http_input');
        const hasExec = flw.some(f => f.startsWith('child_process.'));
        const hasFsWrite = flw.some(f => f.startsWith('fs.write'));
        const hasUDP = flw.includes('udp_outbound');
        
        if (hasInput && hasExec && hasFsWrite && ctx.totalScore < this.config.thresholds.block) {
            ctx.totalScore += 50; // Contextual anomaly aggregation!
        }
        
        if (hasExec && hasUDP && ctx.totalScore < this.config.thresholds.block) {
            ctx.totalScore += 80; // Classic reverse shell exfiltration pattern!
        }

        // 6. Decision Making based on total aggregated score AND explicitly defined policy
        if (ctx.totalScore >= this.config.thresholds.block && policy === 'block') {
            this.triggerAction('blocked', ctx);
        } else if (ctx.totalScore >= this.config.thresholds.log || policy === 'alert') {
            this.triggerAction('logged', ctx);
        }
    }

    private triggerAction(action: 'blocked' | 'logged', ctx: TaintContext) {
        const primaryEvent = ctx.triggeredRules[ctx.triggeredRules.length - 1];
        const now = Date.now();

        // High-volume backpressure & Log Throttling via IP + Attack Signature (Max 1 log per second per IP-Attack combination)
        const throttleKey = `${ctx.requestMeta.ip}_${primaryEvent.attack}`;
        const lastLog = this.logThrottleMap.get(throttleKey) || 0;
        const shouldLog = (now - lastLog) > 1000;

        if (shouldLog) {
            this.logThrottleMap.set(throttleKey, now);

            const eventData = {
                requestId: ctx.requestMeta.requestId,
                action,
                attack: primaryEvent.attack,
                payload: primaryEvent.payload,
                sink: primaryEvent.sink,
                endpoint: ctx.requestMeta.path,
                method: ctx.requestMeta.method,
                ip: ctx.requestMeta.ip,
                score: ctx.totalScore,
                chain: ctx.triggeredRules.length > 1 ? ctx.triggeredRules : undefined
            };

            // Persistent Logs
            this.logger.logEvent(eventData);

            // SIEM WebSocket (Fallback to standard payload interface for demo backward compat)
            this.telemetry.report({
                attack: eventData.attack,
                payload: `[Score: ${eventData.score} | Chain: ${ctx.triggeredRules.length}] ` + eventData.payload,
                path: eventData.endpoint,
                method: eventData.method,
                ip: eventData.ip,
                requestId: eventData.requestId,
                score: eventData.score,
                action: eventData.action,
                chain: eventData.chain
            } as any);
        }

        // Clean up throttle map aggressively to prevent memory leaks in the ShieldRASP runtime itself
        if (this.logThrottleMap.size > 5000) {
            this.logThrottleMap.clear();
        }

        // Fail-open check. Only block if the policy allows.
        if (action === 'blocked') {
            throw new SecurityBlockException(`ShieldRASP: Blocked ${primaryEvent.attack}`, {
                requestId: ctx.requestMeta.requestId,
                score: ctx.totalScore
            });
        }
    }

    private calculateEntropy(str: string): number {
        const len = str.length;
        if (len === 0) return 0;
        const frequencies = new Map<string, number>();
        for (let i = 0; i < len; i++) {
            const char = str[i];
            frequencies.set(char, (frequencies.get(char) || 0) + 1);
        }
        let entropy = 0;
        for (const count of frequencies.values()) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }
        // Normalize against max possible entropy for this length (Math.log2(len)) to get a 0.0 - 1.0 ratio
        const maxEntropy = Math.log2(Math.min(len, 256)); // Base on byte range since we mostly handle ascii/hex
        return maxEntropy > 0 ? entropy / maxEntropy : 0;
    }
}
