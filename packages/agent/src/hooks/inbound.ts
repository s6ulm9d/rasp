const { Hook } = require('require-in-the-middle');
import { taintStorage, TaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';
import { StreamReconstructor } from '../analyzer/StreamReconstructor';

export function setupInboundHook(engine: DetectionEngine) {
    Hook(['http'], (exports: any) => {
        const originalCreateServer = exports.createServer;

        exports.createServer = function (this: any, ...args: any[]) {
            const originalHandler = args[0];
            if (typeof originalHandler === 'function') {
                args[0] = function (req: any, res: any) {
                    const ctx = new TaintContext();
                    let hookHandled = false;

                    // 1. Setup Request Metadata
                    ctx.requestMeta.method = req.method || 'GET';
                    ctx.requestMeta.path = req.url || '/';
                    ctx.requestMeta.ip = req.socket.remoteAddress || '127.0.0.1';

                    const sendBlockResponse = (error: any) => {
                        if (hookHandled) return;
                        hookHandled = true;

                        try {
                            if (!res.headersSent) {
                                res.writeHead(403, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({
                                    error: 'Blocked',
                                    message: error.message || 'Security Block',
                                    details: error.details
                                }));
                            }
                        } catch (e) {}

                        // Force all further response methods to be no-ops to prevent ERR_HTTP_HEADERS_SENT
                        const noop = () => {};
                        res.setHeader = noop as any;
                        res.removeHeader = noop as any;
                        res.writeHead = noop as any;
                        res.write = noop as any;
                        res.end = noop as any;

                        try {
                            if (req.socket && !req.socket.destroyed) {
                                req.socket.destroy();
                            }
                        } catch (e) {}
                    };

                    // 2. Taint Query Params & Headers
                    try {
                        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
                        url.searchParams.forEach((val, key) => ctx.taint(val, `http.query.${key}`));
                    } catch (e) { }

                    Object.entries(req.headers).forEach(([key, val]) => {
                        if (typeof val === 'string') ctx.taint(val, `http.header.${key}`);
                    });

                    // 2c. Early Scan of Query/Headers
                    try {
                        engine.scanContext(ctx);
                    } catch (e: any) {
                        if (e.name === 'SecurityBlockException') {
                            return sendBlockResponse(e);
                        }
                        // FAIL CLOSED on internal detection error
                        return sendBlockResponse({ message: 'INTERNAL_SECURITY_FAILSAFE', details: { err: e.message }});
                    }

                    if (hookHandled) return;

                    // Execute request processing within the Taint async context
                    const self = this;
                    return taintStorage.run(ctx, () => {
                        try {
                            // 3. Delegate Body Reconstruction and Preflight validation (Blocks before framework routing)
                            return StreamReconstructor.interceptRequest(req, res, ctx, engine, (q: any, r: any) => {
                                if (hookHandled) return;
                                return originalHandler.call(self, q, r);
                            }, [req, res], self);
                        } catch (err: any) {
                            if (err.name === 'SecurityBlockException') {
                                return sendBlockResponse(err);
                            }
                            // FAIL CLOSED on internal detection error
                            return sendBlockResponse({ message: 'INTERNAL_SECURITY_FAILSAFE', details: { err: err.message }});
                        }
                    });
                };
            }
            return originalCreateServer.apply(this, args);
        };
        return exports;
    });
}
