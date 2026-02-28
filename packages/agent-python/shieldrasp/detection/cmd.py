import re
from shieldrasp.taint.context import is_tainted, get_taint_context

SHELL_METACHARS = re.compile(r'[;|&`$><\n\\]|\$\(')

def detect_cmd_injection(command_args, ctx=None):
    if not ctx:
        ctx = get_taint_context()
        
    for arg in command_args:
        if isinstance(arg, str):
            matched = SHELL_METACHARS.search(arg) is not None
            tainted = is_tainted(arg)
            
            if matched and tainted:
                return {
                    "blocked": True,
                    "matched": True,
                    "type": "Command Injection",
                    "confidence": 0.99,
                    "cwe": "CWE-78",
                    "payload": arg
                }
    return {"blocked": False, "matched": False}
