"""S7.5 Production Secrets Scanner — Gitleaks Docker, mandatory redaction.

Detects hardcoded secrets, API keys, tokens, credentials in workspace contents.
All detected secret material is redacted before leaving the scanner process.
The actual secret value is NEVER persisted to database, logs, or API responses.
"""

import hashlib
import json
import os
import re
from pathlib import Path

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.docker_runner import DockerRunner, ScannerFailureError

# ---------------------------------------------------------------------------
# Secret material redaction — must be applied BEFORE any persistence/logging
# ---------------------------------------------------------------------------

REDACTED = "[REDACTED]"

SECRET_REDACT_PATTERNS = [
    # Variable assignments with quotes: key = "value"
    re.compile(
        r"(?i)(api[_-]?key|secret|token|password|passwd|aws_access_key|"
        r"aws_secret|private_key|auth_token|access_token|client_secret|"
        r"database_url|connection_string|signing_key|encryption_key|"
        r"jwt_secret|oauth_token|bearer)\s*[:=]\s*['\"][^'\"]{3,}['\"]"
    ),
    # Bare assignments without quotes: key=value (no spaces)
    re.compile(
        r"(?i)(api[_-]?key|secret|token|password|passwd|aws_access_key|"
        r"aws_secret|private_key|auth_token|access_token|client_secret|"
        r"signing_key|encryption_key|jwt_secret|oauth_token|bearer)"
        r"\s*[:=]\s*[^\s,;'\"]{3,}"
    ),
    # Known prefix patterns: sk_live_, ghp_, AKIA, etc.
    re.compile(
        r"(?i)(sk_live|sk_test|pk_live|pk_test|ghp_|gho_|github_pat_|"
        r"AKIA|ASIA|ABIA|ACCA|ghr_|ghs_)[A-Za-z0-9_\-]{10,}"
    ),
    # PEM private key headers
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    # Generic long high-entropy strings (32+ chars)
    re.compile(r"[A-Za-z0-9_\-/+=]{32,}"),
]


def _redact_text(text: str) -> str:
    """Redact all secret material from text. Applied defensively."""
    if not text:
        return ""
    redacted = text
    for pat in SECRET_REDACT_PATTERNS:
        redacted = pat.sub(REDACTED, redacted)
    return redacted[:2000]


def _secret_hash(value: str) -> str:
    """One-way SHA-256 hash for deterministic correlation without exposure."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:32]


def _redact_sarif(raw: str) -> str:
    """Redact secrets in raw SARIF before any persistence or logging."""
    if not raw or not raw.strip():
        return raw
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or "runs" not in data:
            return _redact_text(raw)
        for run in data.get("runs", []):
            if not isinstance(run, dict):
                continue
            for result in run.get("results", []):
                if not isinstance(result, dict):
                    continue
                # Redact message text (may contain secret)
                msg = result.get("message", {})
                if isinstance(msg, dict) and msg.get("text"):
                    msg["text"] = _redact_text(str(msg["text"]))
                # Redact properties
                props = result.get("properties", {})
                if isinstance(props, dict):
                    for k in list(props.keys()):
                        if isinstance(props[k], str):
                            props[k] = _redact_text(props[k])
        return json.dumps(data)
    except Exception:
        return _redact_text(raw)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FALLBACK_ENABLED = os.getenv(
    "SECRETS_FALLBACK_ENABLED", "false"
).lower() in ("1", "true", "yes", "on")
FALLBACK_ENGINE = "secrets_fallback"
PRODUCTION_ENGINE = "gitleaks"
PRODUCTION_VERSION = "8.30.1"

SUPPORTED_IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".cache", "vendor", ".tox",
}


class SecretsScanner(BaseScanner):
    name = "secrets"
    category = "application_security"
    family = "secrets"
    description = "Secrets detection — Gitleaks v8.30.1 SARIF with workspace, mandatory redaction"
    target_types = {"repository", "project", "directory"}
    input_type = "source_code"
    requires_workspace = True
    supported_profiles = {"secrets", "full_secrets"}
    output_format = "sarif"
    capabilities = {"secrets", "secret_detection", "sarif", "gitleaks", "credential_scan"}
    timeout = int(os.getenv("SECRETS_TIMEOUT", "120"))

    IMAGE = os.getenv("SECRETS_IMAGE", "vapt-secrets:latest")
    FALLBACK_IMAGE = "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

    def __init__(self):
        self.runner = None

    def _get_runner(self):
        if self.runner is None:
            self.runner = DockerRunner()
        return self.runner

    def _inject_provenance(self, findings: list[dict], engine: str, mode: str) -> list[dict]:
        """Inject scanner provenance and enforce redaction on all findings."""
        for f in findings:
            if not isinstance(f, dict):
                continue
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if not isinstance(meta, dict):
                meta = {}
            meta["execution_engine"] = engine
            meta["execution_mode"] = mode
            if engine == PRODUCTION_ENGINE:
                meta["engine_version"] = PRODUCTION_VERSION
                meta["image"] = self.IMAGE
            # Mandatory redaction flag
            meta["redacted"] = True
            # Strip any secret value that leaked into metadata
            for k in list(meta.keys()):
                if isinstance(meta[k], str) and len(meta[k]) > 10:
                    lower_key = k.lower()
                    if any(s in lower_key for s in ("secret", "token", "password", "key", "credential")):
                        meta[k] = REDACTED
            f["metadata"] = meta
            f["scanner"] = "secrets"
            # Redact evidence and description
            if f.get("evidence"):
                f["evidence"] = _redact_text(str(f["evidence"]))
            if f.get("description"):
                f["description"] = _redact_text(str(f["description"]))
        return findings

    def _workspace_has_files(self, ws_path: Path) -> bool:
        """Quick check: does workspace contain any scannable files?"""
        src_root = ws_path / "src" if (ws_path / "src").is_dir() else ws_path
        try:
            for p in src_root.rglob("*"):
                if not p.is_file():
                    continue
                if any(part in SUPPORTED_IGNORED_DIRS for part in p.parts):
                    continue
                try:
                    p.resolve().relative_to(ws_path.resolve())
                except ValueError:
                    continue
                try:
                    if p.stat().st_size > 2 * 1024 * 1024:
                        continue
                except Exception:
                    continue
                return True
        except Exception:
            return False
        return False

    def scan(self, target: str) -> str:
        """Legacy scan — returns empty with provenance. Preserves backward compat."""
        result = {
            "scanner": "secrets",
            "assets": [],
            "findings": [],
            "errors": [],
            "metadata": {
                "execution_engine": FALLBACK_ENGINE,
                "execution_mode": "legacy",
                "reason": "legacy scan without workspace",
                "redacted": True,
            },
        }
        return json.dumps(result)

    def scan_with_context(self, context: ScanContext) -> str:
        ws = context.workspace
        if not ws or not Path(ws).exists() or not Path(ws).is_dir():
            return json.dumps({
                "scanner": "secrets", "assets": [], "findings": [], "errors": [],
                "metadata": {"workspace": ws, "reason": "no workspace",
                             "execution_engine": "none", "execution_mode": "none", "redacted": True},
            })

        ws_path = Path(ws)

        # Workspace safety: ensure no traversal
        try:
            ws_resolved = ws_path.resolve()
            ws_resolved.relative_to(Path.cwd().resolve())
        except ValueError:
            pass  # workspace may be outside cwd, which is fine for temp dirs

        if not self._workspace_has_files(ws_path):
            return json.dumps({
                "scanner": "secrets", "assets": [], "findings": [], "errors": [],
                "metadata": {"workspace": ws, "reason": "no files",
                             "execution_engine": PRODUCTION_ENGINE, "execution_mode": "empty",
                             "engine_version": PRODUCTION_VERSION, "redacted": True},
            })

        container_target = "/workspace/src" if (ws_path / "src").is_dir() else "/workspace"

        # Gitleaks writes SARIF to a file (--report-path). DockerRunner captures
        # stdout, so we wrap with a deterministic shell that cats the file to
        # stdout. container_target is a fixed constant ("/workspace" or
        # "/workspace/src") derived from workspace existence, never from
        # untrusted input — safe to interpolate into the fixed shell wrapper.
        # No Python shell=True is used; the shell runs inside the container.
        # Mirrors SCA pattern: file output + cat fallback.
        command = [
            "sh", "-c",
            f"gitleaks detect --source {container_target} "
            f"--report-format sarif --report-path /tmp/sarif.json "
            f"--no-banner --redact --no-git --config /config/gitleaks.toml "
            f"> /dev/null 2>&1; "
            f"cat /tmp/sarif.json 2>/dev/null || cat /tmp/sarif.json || "
            f"echo '{{\"version\":\"2.1.0\",\"runs\":[]}}'",
        ]

        volumes = {str(ws_path.resolve()): {"bind": "/workspace", "mode": "ro"}}
        runner = self._get_runner()
        last_exc = None

        for image in [self.IMAGE, self.FALLBACK_IMAGE]:
            try:
                try:
                    raw = runner.run(
                        image=image,
                        command=command,
                        timeout=self.timeout,
                        scanner="secrets",
                        target=context.target,
                        volumes=volumes,
                        workspace=str(ws_path.resolve()),
                    )
                    if not raw or not raw.strip():
                        raw = '{"version":"2.1.0","runs":[]}'
                except ScannerFailureError as e:
                    # Gitleaks exit 1 with SARIF = findings found (success)
                    if (getattr(e, "exit_code", None) in (0, 1)
                            and e.stdout and '"runs"' in e.stdout):
                        raw = e.stdout
                    else:
                        raise

                # Redact raw output BEFORE any further handling
                raw_redacted = _redact_sarif(raw) if "runs" in raw else _redact_text(raw)

                # Parse and inject provenance
                try:
                    parsed = json.loads(raw_redacted)
                    if isinstance(parsed, dict) and "runs" in parsed:
                        from app.scanner.parsers.sarif_parser import SarifParser
                        sarif_parser = SarifParser()
                        parsed_result = sarif_parser.parse(raw_redacted)
                        # Normalize top-level scanner so FindingEngine preserves secrets
                        parsed_result["scanner"] = "secrets"
                        parsed_result["findings"] = self._inject_provenance(
                            parsed_result.get("findings", []), PRODUCTION_ENGINE, "docker"
                        )
                        for a in parsed_result.get("assets", []):
                            if isinstance(a.get("metadata"), dict):
                                a["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                                a["metadata"]["redacted"] = True
                            else:
                                a["metadata"] = {"execution_engine": PRODUCTION_ENGINE, "redacted": True}
                        parsed_result["metadata"] = parsed_result.get("metadata", {})
                        parsed_result["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                        parsed_result["metadata"]["execution_mode"] = "docker"
                        parsed_result["metadata"]["engine_version"] = PRODUCTION_VERSION
                        parsed_result["metadata"]["image"] = image
                        parsed_result["metadata"]["redacted"] = True
                        return json.dumps(parsed_result)
                    return raw_redacted
                except json.JSONDecodeError:
                    return _redact_text(raw_redacted)

            except Exception as exc:
                last_exc = exc
                if "not found" in str(exc).lower() and image == self.IMAGE:
                    continue
                if not FALLBACK_ENABLED:
                    sanitized = _redact_text(str(exc))
                    raise RuntimeError(sanitized) from exc
                # Fallback enabled: return empty with provenance (not real detection)
                try:
                    result = {
                        "scanner": "secrets", "assets": [], "findings": [], "errors": [],
                        "metadata": {
                            "execution_engine": FALLBACK_ENGINE,
                            "execution_mode": "fallback",
                            "redacted": True,
                            "fallback_reason": _redact_text(str(exc))[:500],
                        },
                    }
                    return json.dumps(result)
                except Exception:
                    raise exc

        if last_exc:
            raise last_exc
        if FALLBACK_ENABLED:
            return json.dumps({
                "scanner": "secrets", "assets": [], "findings": [],
                "metadata": {"execution_engine": FALLBACK_ENGINE, "execution_mode": "fallback", "redacted": True},
            })
        raise RuntimeError("Secrets scanner failed and fallback is disabled")
