import os
import sys

if os.environ.get("RASP_KEY"):
    try:
        from shieldrasp import loader
        loader.load()
    except Exception as e:
        sys.stderr.write(f"[ShieldRASP] Auto-load failed: {e}\n")
