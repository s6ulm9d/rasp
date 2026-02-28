from shieldrasp.taint.context import get_taint_context, TaintLabel
import time

def taint_object(obj, source_name: str):
    try:
        ctx = get_taint_context()
        ctx.tainted_objects[obj] = TaintLabel(
            sources=[source_name],
            timestamp=time.time()
        )
    except Exception:
        pass
