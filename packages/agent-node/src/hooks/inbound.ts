const { Hook } = require('require-in-the-middle');
import { taintStorage, TaintContext } from '../taint/context';
import { AgentConfig } from '../config';
import { TelemetryClient } from '../telemetry/client';

export function hookInbound(config: AgentConfig, telemetry: TelemetryClient) {
    Hook(['http'], (exports: any) => {
        const originalCreateServer = exports.createServer;

        exports.createServer = function (this: any, ...args: any[]) {
            const originalHandler = args[0];
            if (typeof originalHandler === 'function') {
                args[0] = function (req: any, res: any) {
                    const ctx = new TaintContext();

                    // Basic taint for query params and path
                    try {
                        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
                        url.searchParams.forEach((val, key) => {
                            // Taint the value string
                            ctx.taintedObjects.set(val, {
                                sources: ['http.query'],
                                path: [key],
                                timestamp: Date.now()
                            });
                        });

                        // Metadata for the request
                        ctx.requestMeta = {
                            userId: '',
                            sessionId: '',
                            sourceIp: req.socket.remoteAddress || '',
                            requestId: Math.random().toString(36).substring(7),
                            httpMethod: req.method || '',
                            httpPath: url.pathname
                        };
                    } catch (e) {
                        // ignore malformed URLs
                    }

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
