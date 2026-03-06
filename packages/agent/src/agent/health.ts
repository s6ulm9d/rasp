import { AgentConfig } from '../config';

export class HealthMonitor {
  private interval: NodeJS.Timeout | null = null;
  constructor(private config: AgentConfig) {}

  start() {
    this.interval = setInterval(() => {
      // Health check pings
    }, 10000);
    this.interval.unref();
  }

  stop() {
    if (this.interval) clearInterval(this.interval);
  }
}