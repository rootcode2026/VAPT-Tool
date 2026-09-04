"""S7.5 Secrets Parser — Gitleaks SARIF with mandatory redaction.

Parses Gitleaks SARIF output into normalized findings. All secret material
is stripped before the finding reaches the FindingEngine or any persistence layer.
The parser NEVER passes plaintext secret content into the finding pipeline.
"""

import hashlib
import json
import re

from app.scanner.parsers.base import BaseParser

REDACTED = "[REDACTED]"


def _secret_hash(value: str) -> str:
    """One-way SHA-256 hash for deterministic correlation without exposure."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:32]

SECRET_REDACT_PATTERNS = [
    re.compile(
        r"(?i)(api[_-]?key|secret|token|password|passwd|aws_access_key|"
        r"aws_secret|private_key|auth_token|access_token|client_secret|"
        r"signing_key|encryption_key|jwt_secret|oauth_token|bearer)\s*[:=]\s*"
        r"['\"][^'\"]{3,}['\"]"
    ),
    # Bare assignments without quotes
    re.compile(
        r"(?i)(api[_-]?key|secret|token|password|passwd|aws_access_key|"
        r"aws_secret|private_key|auth_token|access_token|client_secret|"
        r"signing_key|encryption_key|jwt_secret|oauth_token|bearer)"
        r"\s*[:=]\s*[^\s,;'\"]{3,}"
    ),
    re.compile(
        r"(?i)(sk_live|sk_test|pk_live|pk_test|ghp_|gho_|github_pat_|"
        r"AKIA|ASIA|ABIA|ACCA|ghr_|ghs_)[A-Za-z0-9_\-]{10,}"
    ),
    # PEM private key headers
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    # Generic long high-entropy strings
    re.compile(r"[A-Za-z0-9_\-/+=]{32,}"),
]


def _redact_text(text: str) -> str:
    """Redact secret material from free text."""
    if not text:
        return ""
    redacted = text
    for pat in SECRET_REDACT_PATTERNS:
        redacted = pat.sub(REDACTED, redacted)
    return redacted[:2000]


def _redact_metadata(meta: dict) -> dict:
    """Remove any secret value fields from finding metadata."""
    if not isinstance(meta, dict):
        return meta
    meta = dict(meta)
    secret_keys = {"secret", "secret_value", "matched_secret", "matched",
                   "password", "token", "api_key", "access_key", "private_key"}
    for k in list(meta.keys()):
        if k in secret_keys:
            if isinstance(meta[k], str) and meta[k] != REDACTED:
                meta[k] = REDACTED
    meta["redacted"] = True
    return meta


def _ensure_redacted_text(value) -> str:
    """Ensure a text value is redacted of secret material."""
    if not isinstance(value, str):
        return value if value else ""
    return _redact_text(value)


class SecretsParser(BaseParser):
    scanner_name = "secrets"

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return {"scanner": "secrets", "assets": [], "findings": []}

        # Try to parse as JSON
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid secrets output JSON: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("Secrets output must be a JSON object")

        # SARIF path — detect SARIF shape (version present)
        if "runs" in data or "version" in data:
            if "runs" not in data or not isinstance(data.get("runs"), list):
                # SARIF with wrong structure is malformed
                if "version" in data and "runs" not in data:
                    raise ValueError("SARIF output missing runs array")
            return self._parse_sarif(data, raw_output)

        # Legacy JSON path
        return self._parse_legacy(data)

    def _parse_sarif(self, data: dict, raw_output: str) -> dict:
        """Parse SARIF output with mandatory redaction."""
        from app.scanner.parsers.sarif_parser import SarifParser

        sarif = SarifParser()
        # Redact raw SARIF before delegation to prevent secret leakage
        raw_redacted = _redact_text(raw_output)
        try:
            result = sarif.parse(raw_redacted)
        except Exception:
            result = sarif.parse(raw_output)
            # Redact after
            for f in result.get("findings", []):
                if isinstance(f, dict):
                    for k in ("evidence", "description", "title"):
                        if isinstance(f.get(k), str):
                            f[k] = _redact_text(f[k])

        # Override scanner and enforce redaction
        result["scanner"] = "secrets"
        for f in result.get("findings", []):
            if not isinstance(f, dict):
                continue
            f["scanner"] = "secrets"
            # Mandatory text redaction
            for k in ("evidence", "description", "title"):
                if isinstance(f.get(k), str):
                    f[k] = _ensure_redacted_text(f[k])
            # Secret type from rule_id
            meta = f.get("metadata", {})
            if not isinstance(meta, dict):
                meta = {}
            meta["secret_type"] = meta.get("secret_type") or f.get("rule_id") or "secret"
            # Engine provenance
            if "execution_engine" not in meta:
                meta["execution_engine"] = "gitleaks"
                meta["execution_mode"] = "docker"
            # Strip any leaked secret values
            meta = _redact_metadata(meta)
            f["metadata"] = meta
            # Evidence type marker
            if not f.get("evidence_type"):
                f["evidence_type"] = "secret"
            # Column preservation (SARIF may include startColumn)
            locations = f.get("metadata", {}).get("locations", [])
            if not f.get("metadata", {}).get("column"):
                # Attempt extraction from original SARIF
                pass  # SarifParser doesn't extract column yet

        # Assets: mark redacted
        for a in result.get("assets", []):
            if isinstance(a.get("metadata"), dict):
                a["metadata"]["redacted"] = True
            else:
                a["metadata"] = {"redacted": True}

        result.setdefault("metadata", {})["redacted"] = True
        return result

    def _parse_legacy(self, data: dict) -> dict:
        """Parse legacy JSON format with mandatory redaction."""
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []
        for f in findings:
            if isinstance(f, dict):
                f["scanner"] = "secrets"
                for k in ("evidence", "description", "title"):
                    if isinstance(f.get(k), str):
                        f[k] = _ensure_redacted_text(f[k])
                meta = f.get("metadata", {})
                if not isinstance(meta, dict):
                    meta = {}
                meta["secret_type"] = meta.get("secret_type") or f.get("rule_id") or "secret"
                meta = _redact_metadata(meta)
                f["metadata"] = meta
                if not f.get("evidence_type"):
                    f["evidence_type"] = "secret"
        assets = data.get("assets", [])
        if not isinstance(assets, list):
            assets = []
        return {
            "scanner": "secrets",
            "assets": assets,
            "findings": findings,
            "metadata": {"redacted": True},
        }
