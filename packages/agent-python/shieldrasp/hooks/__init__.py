from .subprocess_hook import hook_subprocess
from .sqlite_hook import hook_sqlite
import logging

def load_hooks(config, telemetry, health):
    try:
        hook_subprocess(config, telemetry)
        try:
            hook_sqlite(config, telemetry)
        except ImportError:
            pass # sqlite3 might not be used
        # Apply other hooks (os, requests, sqlalchemy, django, flask) similarly
    except Exception as e:
        logging.error(f"[ShieldRASP] Error loading hooks: {e}. Fail open active.")
