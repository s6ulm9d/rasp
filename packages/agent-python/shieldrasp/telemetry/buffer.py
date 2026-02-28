import threading

class EventBuffer:
    def __init__(self, flush_callback):
        self.events = []
        self.max_events = 500
        self.max_duration = 5.0
        self.flush_callback = flush_callback
        self.lock = threading.Lock()
        self.timer = None

    def add(self, event):
        with self.lock:
            self.events.append(event)
            if len(self.events) >= self.max_events:
                self._flush_unlocked()
            elif not self.timer:
                self.timer = threading.Timer(self.max_duration, self.flush)
                self.timer.start()

    def flush(self):
        with self.lock:
            self._flush_unlocked()

    def _flush_unlocked(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None
        if self.events:
            payload = list(self.events)
            self.events.clear()
            threading.Thread(target=self.flush_callback, args=(payload,), daemon=True).start()
