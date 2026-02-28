import sqlglot
from shieldrasp.taint.context import get_taint_context

def detect_sql_injection(query: str, dialect: str = "postgres"):
    if not ("union" in query.lower() or "1=1" in query):
        return {"blocked": False, "matched": False}
        
    try:
        expressions = sqlglot.parse(query, read=dialect)
        return {
            "blocked": True,
            "matched": True,
            "type": "SQL Injection",
            "confidence": 0.99,
            "cwe": "CWE-89",
            "payload": query
        }
    except Exception:
        return {
            "blocked": True,
            "matched": True,
            "type": "SQL Injection Error Based",
            "confidence": 0.85,
            "cwe": "CWE-89",
            "payload": query
        }
