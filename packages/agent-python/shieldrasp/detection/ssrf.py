import socket
from urllib.parse import urlparse
from shieldrasp.taint.context import is_tainted

BLOCKED_RANGES = ["127.", "10.", "172.16.", "192.168.", "169.254."]

def detect_ssrf(url: str):
    if not is_tainted(url):
        return {"blocked": False, "matched": False}
        
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if not hostname:
        return {"blocked": False, "matched": False}
        
    if hostname == "localhost" or hostname.endswith(".internal"):
        return _block(url)
        
    try:
        ip = socket.gethostbyname(hostname)
        for r in BLOCKED_RANGES:
            if ip.startswith(r):
                return _block(url)
    except socket.error:
        pass
        
    return {"blocked": False, "matched": False}

def _block(url):
    return {
        "blocked": True,
        "matched": True,
        "type": "SSRF",
        "confidence": 0.99,
        "cwe": "CWE-918",
        "payload": url
    }
