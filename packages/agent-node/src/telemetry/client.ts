import crypto from 'crypto';
import { AgentConfig } from '../config';
import { EventBuffer } from './buffer';
import { io, Socket } from 'socket.io-client';

export class TelemetryClient {
  private buffer: EventBuffer;
  private socket: Socket;

  constructor(private config: AgentConfig) {
    this.buffer = new EventBuffer((events) => this.dispatchBatch(events));
    const url = `http://${this.config.endpoint || 'localhost:50052'}`;
    this.socket = io(url, { reconnection: true });

    this.socket.on('connect', () => {
      console.log(`[ShieldRASP] Telemetry connected to ${url}`);
    });

    this.socket.on('connect_error', (error) => {
      // Fail silent but log in debug
    });
  }

  sendEvent(event: any) {
    const { getTaintContext } = require('../taint/context');
    const ctx = getTaintContext();
    if (ctx && ctx.requestMeta) {
      event.http_path = ctx.requestMeta.httpPath;
      event.source_ip = ctx.requestMeta.sourceIp;
      event.method = ctx.requestMeta.httpMethod;
    }
    event.api_key = this.config.apiKey;
    event.event_id = crypto.randomUUID();
    event.timestamp = new Date().toISOString();
    this.buffer.add(event);
  }

  private dispatchBatch(events: any[]) {
    if (this.socket.connected) {
      for (const event of events) {
        this.socket.emit('telemetry', JSON.stringify(event));
      }
    }
  }
}