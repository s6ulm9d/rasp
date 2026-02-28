export class EventBuffer {
  private events: any[] = [];
  private maxEvents = 500;
  private maxDurationMs = 5000;
  private timer: NodeJS.Timeout | null = null;
  private flushCallback: (events: any[]) => void;

  constructor(flushCallback: (events: any[]) => void) {
    this.flushCallback = flushCallback;
  }

  add(event: any) {
    this.events.push(event);
    if (this.events.length >= this.maxEvents) {
      this.flush();
    } else if (!this.timer) {
      this.timer = setTimeout(() => this.flush(), this.maxDurationMs);
    }
  }

  flush() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.events.length > 0) {
      const payload = [...this.events];
      this.events = [];
      this.flushCallback(payload);
    }
  }
}