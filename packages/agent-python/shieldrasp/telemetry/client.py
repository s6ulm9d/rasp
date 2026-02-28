import uuid
from shieldrasp.telemetry.buffer import EventBuffer
import json

def redact(obj):
    fields = ['password', 'email', 'token', 'authorization', 'ssn', 'credit_card']
    s = json.dumps(obj)
    for f in fields:
        s = s.replace(f'"{f}":"', f'"{f}":"[REDACTED]"')
    return json.loads(s)

class TelemetryClient:
    def __init__(self, config):
        self.config = config
        self.buffer = EventBuffer(self.dispatch_batch)

    def send_event(self, event):
        safe_event = redact(event)
        safe_event['api_key'] = self.config.api_key
        safe_event['event_id'] = str(uuid.uuid4())
        self.buffer.add(safe_event)

    def dispatch_batch(self, events):
        pass
