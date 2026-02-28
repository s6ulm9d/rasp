import crypto from 'crypto';
import { AgentConfig } from '../config';
import { EventBuffer } from './buffer';

export class TelemetryClient {
  private buffer: EventBuffer;
  
  constructor(private config: AgentConfig) {
    this.buffer = new EventBuffer((events) => this.dispatchBatch(events));
  }

  sendEvent(event: any) {
    event.api_key = this.config.apiKey;
    event.event_id = crypto.randomUUID();
    this.buffer.add(event);
  }

  private dispatchBatch(events: any[]) {
    // gRPC dispatch implementation would go here
  }
}