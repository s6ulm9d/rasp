from .config import AgentConfig, validate_config
from .telemetry.client import TelemetryClient
from .agent.health import HealthMonitor
from .hooks import load_hooks

_initialized = False

def init(config: AgentConfig):
    global _initialized
    if _initialized:
        return
        
    validate_config(config)
    telemetry = TelemetryClient(config)
    health = HealthMonitor(config)
    
    health.start()
    load_hooks(config, telemetry, health)
    
    _initialized = True
