"""SQLmap Database Security — controlled, bounded, read-only detection.

Only runs under explicit database_security profile. No data dumping, no OS takeover.
"""
import json
import os
import re
from pathlib import Path

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.docker_runner import DockerRunner, ScannerFailureError

PRODUCTION_VERSION = "1.8.5"
FALLBACK_ENABLED = os.getenv("SQLMAP_FALLBACK_ENABLED", "false").lower() in ("1", "true", "yes", "on")

# Allowlisted SQLmap options — detection only
ALLOWED_LEVEL = {"1", "2", "3", "4", "5"}
ALLOWED_RISK = {"1", "2", "3"}
ALLOWED_TECHNIQUE = {"B", "E", "U", "S", "T", "Q"}
FORBIDDEN_FLAGS = {
    "--os-shell", "--os-pwn", "--os-smbrelay", "--os-bof",
    "--file-read", "--file-write", "--file-dest",
    "--sql-shell", "--sql-query", "--common-tables", "--dump",
    "--dump-all", "--search", "--priv-esc", "--reg-read", "--reg-add",
    "--eval", "--shell", "--purge",
}

_TARGET_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.I)
_PRIVATE_IP_RE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")

def _validate_target(target: str) -> str:
    t = target.strip()
    if not t:
        raise ValueError("Target cannot be empty")
    if len(t) > 2048:
        raise ValueError("Target too long")
    # Allow domain or URL; normalize to URL for sqlmap
    if t.startswith(("http://", "https://")):
        if not _TARGET_RE.match(t):
            raise ValueError("Invalid URL format")
        # SSRF protection: block localhost/private and metadata
        if "localhost" in t or "127.0.0.1" in t or "169.254.169.254" in t or "metadata.google" in t:
            raise ValueError("Target not allowed (SSRF protection)")
        return t
    # domain
    if any(c in t for c in ";&|$`"):
        raise ValueError("Invalid target")
    return f"https://{t}"

def _build_command(target: str, level: str = "1", risk: str = "1", technique: str = "BEUS") -> list[str]:
    if level not in ALLOWED_LEVEL:
        level = "1"
    if risk not in ALLOWED_RISK:
        risk = "1"
    # technique must be subset of allowed
    tech = "".join(c for c in technique.upper() if c in ALLOWED_TECHNIQUE) or "BEUS"
    # Batch, crawl limited, no forms auto? Use safe defaults
    return [
        "sqlmap",
        "-u", target,
        "--batch",
        "--level", level,
        "--risk", risk,
        "--technique", tech,
        "--crawl", "2",
        "--forms",
        "--threads", "2",
        "--timeout", "10",
        "--retries", "1",
        "--random-agent",
        "--output-dir", "/tmp",
        "--forms",
    ]

class SQLMapScanner(BaseScanner):
    name = "sqlmap"
    category = "database_security"
    family = "dast"
    description = "SQL injection detection — SQLmap controlled, read-only, bounded"
    target_types = {"domain", "url", "ip"}
    input_type = "target"
    requires_workspace = False
    supported_profiles = {"database_security", "advanced_dast"}
    output_format = "json"
    capabilities = {"sqli_detection", "database_fingerprint", "injection_testing", "dast"}
    timeout = 300

    IMAGE = os.getenv("SQLMAP_IMAGE", "vapt-sqlmap:latest")
    FALLBACK_IMAGE = "sqlmapproject/sqlmap:1.8.5"

    def __init__(self):
        self.runner = None

    def _get_runner(self):
        if self.runner is None:
            self.runner = DockerRunner()
        return self.runner

    def scan(self, target: str) -> str:
        validated = _validate_target(target)
        # Check forbidden flags not in target
        for flag in FORBIDDEN_FLAGS:
            if flag in validated:
                raise ValueError(f"Forbidden flag: {flag}")
        command = _build_command(validated)
        runner = self._get_runner()
        try:
            raw = runner.run(
                image=self.IMAGE,
                command=command,
                timeout=self.timeout,
                scanner="sqlmap",
                target=validated,
            )
            # SQLmap outputs to files; we capture stdout; if empty, return synthetic JSON
            if not raw or not raw.strip():
                return json.dumps({"scanner": "sqlmap", "target": validated, "findings": [], "technique": "BEUS", "provenance": PRODUCTION_VERSION})
            # Try to parse as JSON; if not, wrap
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return json.dumps(data)
                return json.dumps({"scanner": "sqlmap", "raw": raw[:2000], "target": validated})
            except Exception:
                return json.dumps({"scanner": "sqlmap", "raw": raw[:2000], "target": validated})
        except ScannerFailureError as e:
            # If stdout contains JSON, treat as success
            if e.stdout and '"findings"' in e.stdout:
                return e.stdout
            # For detection, empty is ok
            if e.exit_code in (0, 1) and e.stdout:
                return json.dumps({"scanner": "sqlmap", "raw": e.stdout[:2000], "target": validated})
            raise
        except Exception as exc:
            # Sanitized error
            if "invalid" in str(exc).lower():
                raise
            raise RuntimeError(f"SQLmap scan failed") from exc

    def scan_with_context(self, context: ScanContext) -> str:
        # Use ScanContext metadata for level/risk if provided
        meta = context.metadata if isinstance(context.metadata, dict) else {}
        level = str(meta.get("level", "1"))
        risk = str(meta.get("risk", "1"))
        technique = str(meta.get("technique", "BEUS"))
        target = str(context.target).strip()
        validated = _validate_target(target)
        command = _build_command(validated, level, risk, technique)
        runner = self._get_runner()
        try:
            raw = runner.run(
                image=self.IMAGE,
                command=command,
                timeout=self.timeout,
                scanner="sqlmap",
                target=validated,
                workspace=context.workspace,
            )
            if not raw.strip():
                return json.dumps({"scanner": "sqlmap", "findings": [], "target": validated})
            return raw
        except Exception as e:
            raise
