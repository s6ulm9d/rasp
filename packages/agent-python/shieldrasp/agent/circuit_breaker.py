import time

class CircuitBreaker:
    def __init__(self):
        self.timings = {}
        self.disabled_hooks = set()
        self.THRESHOLD_MS = 0.5
        self.SAMPLES = 100

    def record(self, hook_id: str, duration_ms: float):
        if hook_id in self.disabled_hooks:
            return
            
        if hook_id not in self.timings:
            self.timings[hook_id] = []
            
        stats = self.timings[hook_id]
        stats.append(duration_ms)
        
        if len(stats) > self.SAMPLES:
            stats.pop(0)
            
        if len(stats) == self.SAMPLES:
            avg = sum(stats) / self.SAMPLES
            if avg > self.THRESHOLD_MS:
                self.disable_hook(hook_id, avg)

    def disable_hook(self, hook_id: str, avg_duration: float):
        self.disabled_hooks.add(hook_id)

    def is_disabled(self, hook_id: str) -> bool:
        return hook_id in self.disabled_hooks

global_circuit_breaker = CircuitBreaker()
