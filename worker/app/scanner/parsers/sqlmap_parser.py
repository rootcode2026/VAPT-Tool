import json
import re
from app.scanner.parsers.base import BaseParser

class SQLMapParser(BaseParser):
    scanner = "sqlmap"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "sqlmap", "assets": [], "findings": [], "errors": [], "metadata": {"empty": True}}
        # Try JSON
        try:
            data = json.loads(raw_output)
            if isinstance(data, dict) and "findings" in data:
                # Already normalized
                findings = []
                for f in data.get("findings", []):
                    if isinstance(f, dict):
                        findings.append({
                            "scanner": "sqlmap",
                            "title": f.get("title", "SQL Injection"),
                            "description": f.get("description", "Potential SQL injection detected"),
                            "severity": f.get("severity", "high"),
                            "score": 85,
                            "status": "open",
                            "evidence": (f.get("evidence") or f.get("parameter") or "")[:500],
                            "remediation": "Use parameterized queries",
                            "cwe": "CWE-89",
                            "metadata": {"parameter": f.get("parameter"), "endpoint": f.get("endpoint"), "technique": f.get("technique"), "dbms": f.get("dbms")},
                        })
                return {"scanner": "sqlmap", "assets": data.get("assets", []), "findings": findings, "errors": [], "metadata": data.get("metadata", {})}
        except Exception:
            pass
        # Text parsing: look for parameter, injection point
        findings = []
        # Simple regex for parameter
        param_match = re.findall(r"Parameter:\s*([^\s]+)", raw_output)
        endpoint_match = re.search(r"URL:\s*([^\s]+)", raw_output)
        endpoint = endpoint_match.group(1)[:200] if endpoint_match else ""
        for param in set(param_match[:5]):
            if len(param) > 100 or any(c in param for c in ";&|$`"):
                continue
            findings.append({
                "scanner": "sqlmap",
                "title": f"SQL Injection in parameter '{param}'",
                "description": f"Parameter '{param}' at {endpoint} may be vulnerable to SQL injection (detected via safe payload)",
                "severity": "high",
                "score": 85,
                "status": "open",
                "evidence": f"Parameter: {param} | Endpoint: {endpoint} | Technique: BEUS"[:500],
                "remediation": "Use parameterized queries / prepared statements",
                "cwe": "CWE-89",
                "metadata": {"parameter": param, "endpoint": endpoint, "technique": "BEUS"},
            })
        # If no findings but output contains injection, create generic
        if not findings and "sql injection" in raw_output.lower():
            findings.append({
                "scanner": "sqlmap",
                "title": "Potential SQL Injection",
                "description": "SQL injection pattern detected (sanitized evidence)",
                "severity": "high",
                "score": 75,
                "status": "needs_review",
                "evidence": raw_output[:500],
                "remediation": "Review endpoint for SQL injection",
                "cwe": "CWE-89",
                "metadata": {"raw_snippet": raw_output[:200]},
            })
        return {"scanner": "sqlmap", "assets": [], "findings": findings, "errors": [], "metadata": {"raw_length": len(raw_output)}}
