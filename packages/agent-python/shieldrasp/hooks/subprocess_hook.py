import wrapt
import time
from shieldrasp.agent.circuit_breaker import global_circuit_breaker
from shieldrasp.detection.cmd import detect_cmd_injection

class RASPBlockError(Exception):
    pass

def hook_subprocess(config, telemetry):
    @wrapt.patch_function_wrapper('subprocess', 'Popen.__init__')
    def popen_wrapper(wrapped, instance, args, kwargs):
        hook_id = "subprocess.Popen"
        if global_circuit_breaker.is_disabled(hook_id):
            return wrapped(*args, **kwargs)
            
        start = time.time()
        try:
            cmd_args = args[0] if args else kwargs.get('args', [])
            if isinstance(cmd_args, str):
                cmd_args = [cmd_args]
                
            res = detect_cmd_injection(cmd_args)
            if res.get("blocked"):
                telemetry.send_event(res)
                if config.mode == 'protect':
                    raise RASPBlockError(f"RASP Blocked: Command Injection")
            elif res.get("matched"):
                telemetry.send_event(res)
        except RASPBlockError:
            raise
        except Exception:
            pass # Fail open
        finally:
            global_circuit_breaker.record(hook_id, (time.time() - start) * 1000)
            
        return wrapped(*args, **kwargs)
