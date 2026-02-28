import os
from shieldrasp.taint.context import is_tainted, get_taint_context

def detect_path_traversal(path_str: str, jail_dir: str = "/app"):
    if not isinstance(path_str, str):
        return {"blocked": False, "matched": False}
        
    tainted = is_tainted(path_str)
    if not tainted:
        return {"blocked": False, "matched": False}
        
    normalized = os.path.abspath(path_str)
    if not normalized.startswith(os.path.abspath(jail_dir)):
        return {
            "blocked": True,
            "matched": True,
            "type": "Path Traversal",
            "confidence": 0.99,
            "cwe": "CWE-22",
            "payload": path_str
        }
    return {"blocked": False, "matched": False}
