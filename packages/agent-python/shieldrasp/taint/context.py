import contextvars
import weakref
from dataclasses import dataclass, field
from typing import List

@dataclass
class TaintLabel:
    sources: List[str] = field(default_factory=list)
    path: List[str] = field(default_factory=list)
    timestamp: float = 0.0

class TaintContext:
    def __init__(self):
        self.tainted_objects = weakref.WeakKeyDictionary()
        self.request_meta = {
            "user_id": "",
            "session_id": "",
            "source_ip": "",
            "request_id": "",
            "http_method": "",
            "http_path": ""
        }

taint_storage = contextvars.ContextVar('taint_storage', default=None)

def get_taint_context() -> TaintContext:
    ctx = taint_storage.get()
    if ctx is None:
        ctx = TaintContext()
        taint_storage.set(ctx)
    return ctx

def is_tainted(obj) -> bool:
    try:
        ctx = taint_storage.get()
        if ctx is None:
            return False
        return obj in ctx.tainted_objects
    except TypeError:
        return False
