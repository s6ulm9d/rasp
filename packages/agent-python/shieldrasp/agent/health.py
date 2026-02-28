import threading
import time

class HealthMonitor:
    def __init__(self, config):
        self.config = config
        self.running = False

    def start(self):
        self.running = True
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def _monitor_loop(self):
        while self.running:
            time.sleep(10)
