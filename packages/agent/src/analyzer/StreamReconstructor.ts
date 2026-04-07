import { TaintContext } from '../taint/context';
import { DetectionEngine } from '../engine';

const MAX_PAYLOAD_SIZE = 5 * 1024 * 1024; // 5MB Cap
const MAX_WAIT_TIMEOUT = 10000; // 10s Timeout

export class StreamReconstructor {
    public static interceptRequest(req: any, res: any, ctx: TaintContext, engine: DetectionEngine, originalHandler: any, originalArgs: any[], originalThis: any) {
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
            // No body to inspect natively
            try {
                return originalHandler.apply(originalThis, originalArgs);
            } catch (e: any) {
                if (e.name === 'SecurityBlockException') return;
                throw e;
            }
        }

        let chunks: Buffer[] = [];
        let totalSize = 0;
        let lastFragment = Buffer.alloc(0);
        let isAborted = false;

        const timeout = setTimeout(() => {
            if (!isAborted) {
                isAborted = true;
                req.socket?.destroy();
            }
        }, MAX_WAIT_TIMEOUT);

        const cleanup = () => clearTimeout(timeout);

        const fail = (reason: string) => {
            if (isAborted) return false;
            isAborted = true;
            cleanup();
            
            try {
                if (!res.headersSent) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        error: "Forbidden",
                        message: `ShieldRASP Block: ${reason}`,
                        requestId: ctx.requestMeta.requestId
                    }));
                }
            } catch(e) {}
            
            // Stub methods to prevent crashes
            const noop = () => {};
            res.setHeader = noop;
            res.removeHeader = noop;
            res.writeHead = noop;
            res.write = noop;
            res.end = noop;

            try {
                if (req.socket && !req.socket.destroyed) req.socket.destroy();
            } catch(e) {}

            return false;
        };

        const originalEmit = req.emit.bind(req);

        req.emit = function (eventName: string, ...args: any[]) {
            if (isAborted) return false;
            try {
                if (eventName === 'data') {
                    const raw = args[0];
                    if (!Buffer.isBuffer(raw) && typeof raw !== 'string') {
                        return originalEmit.apply(this, [eventName, ...args]);
                    }

                    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
                    totalSize += chunk.length;

                    if (totalSize > MAX_PAYLOAD_SIZE) {
                        return fail('PAYLOAD_TOO_LARGE');
                    }

                    const scanBuffer = Buffer.concat([lastFragment, chunk]);
                    try {
                        engine.scanContext(ctx, scanBuffer.toString('utf8'));
                    } catch (e: any) {
                        if (e.name === 'SecurityBlockException') return fail(e.message);
                        return fail('INTERNAL_SECURITY_FAILSAFE');
                    }

                    if (isAborted) return false;

                    lastFragment = chunk.slice(-512);
                    if (chunks.length < 50) chunks.push(chunk);

                } else if (eventName === 'end') {
                    cleanup();
                    if (chunks.length > 0) {
                        const fullBodyBuffer = Buffer.concat(chunks);
                        const fullBodyString = fullBodyBuffer.toString('utf8');

                        try {
                            ctx.requestMeta.flow.push('http_body_assembled');
                            ctx.taint(fullBodyString, 'http.body.raw');

                            const contentType = (req.headers['content-type'] || '').toLowerCase();
                            if (contentType.includes('application/json')) {
                                const parsed = JSON.parse(fullBodyString);
                                ctx.taint(parsed, 'http.body.json');
                            }
                        } catch (e) {}

                        try {
                            engine.scanContext(ctx, fullBodyString); 
                        } catch (e: any) {
                            if (e.name === 'SecurityBlockException') return fail(e.message);
                            return fail('INTERNAL_SECURITY_FAILSAFE');
                        }
                    }
                }
            } catch (err) {
                return fail(`INTERNAL_SECURITY_FAILSAFE: ${err}`);
            }

            if (isAborted) return false;
            try {
                return originalEmit.apply(this, [eventName, ...args]);
            } catch (err) { return false; }
        };

        // Execute original framework handler
        try {
            originalHandler.apply(originalThis, originalArgs);
        } catch (e: any) {
            if (e.name === 'SecurityBlockException') return fail(e.message);
        }
    }

}
