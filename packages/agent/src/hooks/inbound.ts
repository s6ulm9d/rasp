const { Hook } = require('require-in-the-middle');
import { taintStorage, TaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry';

export function setupInboundHook(config: AgentConfig, telemetry: TelemetryClient) {
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
                    // We taint every chunk that enters the application via the request stream
                    const originalOn = req.on;
                    req.on = function (event: string, listener: any) {
                        if (event === 'data' && typeof listener === 'function') {
                            const wrappedListener = (chunk: any) => {
                                const str = Buffer.isBuffer(chunk) ? chunk.toString() : chunk;
                                if (typeof str === 'string') {
                                    ctx.taint(str, 'http.body');
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
