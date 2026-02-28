import os
from shieldrasp.config import AgentConfig
import shieldrasp

def load():
    api_key = os.environ.get("RASP_KEY")
    if api_key:
        config = AgentConfig(
            api_key=api_key,
            mode=os.environ.get("RASP_MODE", "protect"),
            endpoint=os.environ.get("RASP_URL", "localhost:50051")
        )
        shieldrasp.init(config)
