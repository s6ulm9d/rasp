import wrapt
import time
from shieldrasp.agent.circuit_breaker import global_circuit_breaker
from shieldrasp.detection.sql import detect_sql_injection
from shieldrasp.hooks.subprocess_hook import RASPBlockError

def hook_sqlite(config, telemetry):
    @wrapt.patch_function_wrapper('sqlite3', 'Cursor.execute')
    def execute_wrapper(wrapped, instance, args, kwargs):
        hook_id = "sqlite3.execute"
        if global_circuit_breaker.is_disabled(hook_id):
            return wrapped(*args, **kwargs)
            
        start = time.time()
        try:
            query = args[0] if args else ""
            res = detect_sql_injection(query, dialect="sqlite")
            if res.get("blocked"):
                telemetry.send_event(res)
                if config.mode == 'protect':
                    raise RASPBlockError(f"RASP Blocked: SQL Injection")
            elif res.get("matched"):
                telemetry.send_event(res)
        except RASPBlockError:
            raise
        except Exception:
            pass # Fail open
        finally:
            global_circuit_breaker.record(hook_id, (time.time() - start) * 1000)
            
        return wrapped(*args, **kwargs)
