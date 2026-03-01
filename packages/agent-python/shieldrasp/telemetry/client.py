import uuid
from shieldrasp.telemetry.buffer import EventBuffer
import json
import socketio
import datetime

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
        self.sio = socketio.Client(reconnection=True, reconnection_attempts=0)
        
        endpoint = getattr(config, 'endpoint', 'localhost:50052')
        if ':' not in endpoint:
            endpoint = f"{endpoint}:50052"
        
        try:
            self.sio.connect(f"http://{endpoint}")
        except Exception:
            pass # Fail open, don't crash the main app

    def send_event(self, event):
        safe_event = redact(event)
        safe_event['api_key'] = getattr(self.config, 'api_key', 'default_key')
        safe_event['event_id'] = str(uuid.uuid4())
        safe_event['timestamp'] = datetime.datetime.now().isoformat()
        self.buffer.add(safe_event)

    def dispatch_batch(self, events):
        if self.sio.connected:
            for event in events:
                self.sio.emit('telemetry', json.dumps(event))
