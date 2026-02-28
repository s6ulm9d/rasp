from dataclasses import dataclass
import os

@dataclass
class AgentConfig:
    api_key: str
    mode: str = "protect"
    endpoint: str = "localhost:50051"
    timeout: int = 5000

def validate_config(config: AgentConfig):
    if not config.api_key:
        config.api_key = os.environ.get('RASP_KEY')
    if not config.api_key:
        raise ValueError("[ShieldRASP] Critical Error: api_key is required.")
