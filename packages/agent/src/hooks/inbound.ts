const { Hook } = require('require-in-the-middle');
import { taintStorage, TaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

export function setupInboundHook(engine: DetectionEngine) {
    Hook(['http'], (exports: any) => {
        const originalCreateServer = exports.createServer;

        exports.createServer = function (this: any, ...args: any[]) {
            const originalHandler = args[0];
            if (typeof originalHandler === 'function') {
                args[0] = function (req: any, res: any) {
                    const ctx = new TaintContext();

                    // 1. Setup Request Metadata
                    ctx.requestMeta.method = req.method || 'GET';
                    ctx.requestMeta.path = req.url || '/';
                    ctx.requestMeta.ip = req.socket.remoteAddress || '127.0.0.1';

                    // 2. Taint Query Params
                    try {
                        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
                        url.searchParams.forEach((val, key) => {
                            ctx.taint(val, `http.query.${key}`);
                        });
                    } catch (e) { }

                    // 3. Hook Body (Data Events)
                    const originalOn = req.on;
                    req.on = function (event: string, listener: any) {
                        if (event === 'data' && typeof listener === 'function') {
                            const wrappedListener = (chunk: any) => {
                                const str = Buffer.isBuffer(chunk) ? chunk.toString() : chunk;
                                if (typeof str === 'string') {
                                    ctx.requestMeta.flow.push('http_input');
                                    ctx.taint(str, 'http.body');

                                    // Canary Memory Scraping Protection
                                    const canaries = ['__CANARY_DB_9f8a__', '__CANARY_MEMORY_CAFE__', '__CANARY_CONFIG_BABE__'];
                                    
                                    for (const canary of canaries) {
                                        if (str.includes(canary)) {
                                            ctx.requestMeta.flow.push('memory_scraping_attempt');
                                            try {
                                                engine.evaluate(ctx, {
                                                    attack: 'Anomaly (Memory Scrape)',
                                                    payload: `Runtime Trap Tripped [${canary}]. Attempted dynamic scan of process memory.`,
                                                    sink: 'http.inbound',
                                                    baseScore: 99,
                                                    tainted: true
                                                });
                                            } catch (e: any) {
                                                if (e.name === 'SecurityBlockException') {
                                                    if (!res.headersSent) {
                                                        res.writeHead(403, { 'Content-Type': 'application/json' });
                                                        res.end(JSON.stringify({ error: "Forbidden", message: e.message, details: e.details }));
                                                        res.destroy(); // Safely tear down network pipe
                                                    }
                                                    return; // Stop processing further chunks natively
                                                } else {
                                                    throw e;
                                                }
                                            }
                                        }
                                    }
                                }
                                return listener(chunk);
                            };
                            return originalOn.call(this, event, wrappedListener);
                        }
                        return originalOn.call(this, event, listener);
                    };

                    // Execute request inside the Taint Storage context
                    return taintStorage.run(ctx, () => {
                        return originalHandler.apply(this, [req, res]);
                    });
                };
            }
            return originalCreateServer.apply(this, args);
        };
        return exports;
    });
}
