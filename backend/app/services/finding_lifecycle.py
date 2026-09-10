"""SLA, risk acceptance, remediation, retest services — deterministic, tenant-scoped."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

DEFAULT_SLA_HOURS = {
    "critical": 24,
    "high": 72,
    "medium": 168,
    "low": 336,
    "info": 720,
}

SLA_STATUSES = {"active", "met", "breached", "waived"}
RA_STATUSES = {"requested", "approved", "rejected", "expired", "revoked"}
# D7: remediation workflow reuses FindingRemediation with an additive "blocked" state.
# "completed" means owner-reported completion (NOT verified); verification belongs to D8.
REMEDIATION_STATUSES = {"open", "in_progress", "submitted", "blocked", "completed", "cancelled"}
RETEST_STATUSES = {"requested", "queued", "running", "passed", "failed", "cancelled", "error"}
RETEST_RESULTS = {"passed", "failed", "error"}

REMEDIATION_TRANSITIONS = {
    "open": {"in_progress", "cancelled"},
    "in_progress": {"submitted", "blocked", "cancelled"},
    "blocked": {"in_progress", "cancelled"},
    "submitted": {"completed", "blocked", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}

# One active remediation per finding (D7 includes "blocked" as active).
REMEDIATION_ACTIVE_STATUSES = {"open", "in_progress", "submitted", "blocked"}

# Bounded evidence-reference guardrails (references only, never raw bodies/secrets).
REMEDIATION_EVIDENCE_REF_MAX = 2000
REMEDIATION_BLOCKED_REASON_MAX = 500
_SECRET_REF_PATTERNS = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE", "BEGIN OPENSSH", "aws_secret", "sk_live", "ghp_")


def sanitize_remediation_evidence_ref(value: str | None) -> str | None:
    """Validate a bounded evidence *reference* (ID/URL/summary), not raw evidence.

    Returns the trimmed value or None. Raises ValueError on secret-like content.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if len(s) > REMEDIATION_EVIDENCE_REF_MAX:
        s = s[:REMEDIATION_EVIDENCE_REF_MAX]
    upper = s.upper()
    for pat in _SECRET_REF_PATTERNS:
        if pat in s or pat.upper() in upper:
            raise ValueError("evidence_ref must be a bounded reference, not secret material")
    return s

RETEST_TRANSITIONS = {
    "requested": {"queued", "cancelled"},
    "queued": {"running", "cancelled"},
    "running": {"passed", "failed", "error", "cancelled"},
    "passed": set(),
    "failed": set(),
    "error": set(),
    "cancelled": set(),
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_sla_target_hours(db: Session, organization_id: str, severity: str) -> int:
    from app.models.finding import SLAPolicy

    sev = (severity or "").strip().lower()
    row = (
        db.query(SLAPolicy)
        .filter(SLAPolicy.organization_id == organization_id, SLAPolicy.severity == sev)
        .first()
    )
    if row:
        return int(row.target_hours)
    return int(DEFAULT_SLA_HOURS.get(sev, 168))


def evaluate_sla_status(sla, now: datetime | None = None) -> str:
    now = now or utcnow()
    # Normalize naive datetimes
    due = sla.due_at
    if due is not None and due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    completed = sla.completed_at
    if sla.status in ("met", "waived"):
        return sla.status
    if completed is not None:
        return "met"
    if due is not None and due < now:
        return "breached"
    return "active"


def refresh_sla_breach(db: Session, sla, now: datetime | None = None) -> bool:
    """Mark breached if due passed. Returns True if transitioned."""
    now = now or utcnow()
    current = evaluate_sla_status(sla, now)
    if current == "breached" and sla.status == "active":
        sla.status = "breached"
        sla.breached_at = now
        try:
            sla.updated_at = now
        except Exception:
            pass
        return True
    return False


def check_ra_expired(ra, now: datetime | None = None) -> bool:
    now = now or utcnow()
    if ra.status != "approved":
        return False
    exp = ra.expires_at
    if exp is None:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp <= now


# ---------------------------------------------------------------------------
# D8: verification fingerprinting + evaluation
# ---------------------------------------------------------------------------
# The worker's `fingerprint_finding` (worker/app/services/finding_correlation/
# normalizer.py) is the authoritative finding-identity algorithm. The backend
# cannot import worker code at runtime (separate image), so D8 re-implements
# the *same* canonical payload (identical field set, canonical JSON encoding,
# SHA-256) for baseline/verification-scan comparison. Parity is enforced by
# backend/tests/test_retest_fingerprint_vector.py, which asserts byte-identical
# output against the worker implementation for representative findings.
# Any change on either side must keep the vector test green.

FINGERPRINT_ALGO = "fp-v1"

_FINGERPRINT_FIELDS = (
    "rule_id", "cve", "cwe", "normalized_title", "hostname", "url",
    "port", "parameter", "file", "line", "ip", "asset_type", "asset_value",
)

_CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE[-:]?\s*(\d+)", re.IGNORECASE)

# D8 verification execution is supported only for scanners that run against a
# live target without a populated workspace. Workspace scanners (sast, sca,
# secrets, iac, api) would scan an empty workspace, yield zero findings, and
# produce a FALSE PASSED — so requests for them are rejected explicitly.
# container/sqlmap are excluded: no supported verification profile / parser gap.
RETEST_EXECUTABLE_SCANNERS = {
    "nmap", "nuclei", "http_fingerprint", "zap", "nikto", "tls", "dns", "subdomain",
}

RETEST_SCANNER_PROFILES = {
    "nmap": "quick",
    "nuclei": "web",
    "http_fingerprint": "web",
    "zap": "web",
    "nikto": "web",
    "tls": "web",
    "dns": "web",
    "subdomain": "web",
}


def _collapse_text(value: Any) -> str | None:
    if value is None:
        return None
    t = " ".join(str(value).replace("\r\n", "\n").replace("\r", "\n").split())
    return t or None


def _d8_hostname(value: Any) -> str | None:
    """Mirror worker normalize_hostname (lowercase IDNA, no port/path)."""
    import ipaddress as _ip

    if value is None:
        return None
    text = str(value).strip()
    if "://" in text:
        try:
            from urllib.parse import urlparse as _up

            host = _up(text).hostname
            if not host:
                return None
            text = host
        except Exception:
            return None
    text = text.strip().rstrip(".")
    if not text or any(c in text for c in "/?#@ "):
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = _ip.ip_address(text)
        return str(addr) if addr.version == 4 else addr.compressed
    except ValueError:
        pass
    if ":" in text:
        return None
    try:
        ascii_name = ".".join(
            "*" if label == "*" else label.encode("idna").decode("ascii").lower()
            for label in text.split(".")
        ).rstrip(".")
    except Exception:
        return None
    if len(ascii_name) > 253:
        return None
    if any(not lab or not re.match(r"^(?:[*]|xn--[a-z0-9-]{1,59}|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$", lab) for lab in ascii_name.split(".")):
        return None
    return ascii_name or None


def _d8_url(value: Any) -> str | None:
    """Mirror worker normalize_url (scheme/host canonical, default port dropped)."""
    if value is None:
        return None
    try:
        from urllib.parse import urlparse as _up, urlunparse as _uu

        parsed = _up(str(value).strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https") or not parsed.hostname:
            return None
        host = _d8_hostname(parsed.hostname)
        if not host:
            return None
        try:
            import ipaddress as _ip

            addr = _ip.ip_address(host)
            host = f"[{addr.compressed}]" if addr.version == 6 else str(addr)
        except ValueError:
            pass
        try:
            port = parsed.port
        except Exception:
            return None
        default = 80 if scheme == "http" else 443
        netloc = host if port is None or port == default else f"{host}:{port}"
        path = parsed.path or "/"
        return _uu((scheme, netloc, path, "", parsed.query, ""))[:1024] or None
    except Exception:
        return None


def _d8_ip(value: Any) -> str | None:
    """Mirror worker normalize_ip (compressed textual form)."""
    if value is None:
        return None
    try:
        import ipaddress as _ip

        addr = _ip.ip_address(str(value).strip())
        return str(addr) if addr.version == 4 else addr.compressed
    except ValueError:
        return None


def _d8_port(value: Any) -> str | None:
    """Mirror worker normalize_port (string form, 1-65535)."""
    if value is None or value == "":
        return None
    text = str(value).strip()
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    try:
        port = int(text)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return str(port)


def _d8_file(value: Any) -> str | None:
    """Mirror worker _normalize_file_path (POSIX collapse)."""
    if value is None:
        return None
    from pathlib import PurePosixPath as _PP

    s = str(value).strip()
    if not s:
        return None
    try:
        s = str(_PP(s)).replace("\\", "/")
        s = re.sub(r"/+", "/", s)
        if s.startswith("./"):
            s = s[2:]
        return s.strip() or None
    except Exception:
        return s


def _fp_cve(value: Any) -> str | None:
    if value is None:
        return None
    m = _CVE_RE.search(str(value))
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _fp_cwe(value: Any) -> str | None:
    if value is None:
        return None
    m = _CWE_RE.search(str(value))
    return f"CWE-{m.group(1)}" if m else None


def d8_finding_input(finding) -> dict[str, Any]:
    """Build the canonical fingerprint input from a backend Finding row.

    Location/identity fields come from the finding's persisted metadata
    (extra_data), mirroring the worker normalizer's metadata-first lookup.
    """
    meta = getattr(finding, "extra_data", None) or {}
    if not isinstance(meta, dict):
        meta = {}
    rule_raw = meta.get("rule_id") or meta.get("ruleId") or meta.get("rule")
    rule_id = _collapse_text(rule_raw).upper() if _collapse_text(rule_raw) else None
    line = meta.get("line", meta.get("line_number", meta.get("lineno")))
    try:
        line = int(str(line).strip()) if line is not None else None
    except Exception:
        line = None
    url = _d8_url(meta.get("url") or meta.get("uri") or meta.get("matched_at") or meta.get("site"))
    if not url:
        ev = getattr(finding, "evidence", None)
        if ev:
            m = re.search(r"https?://[^\s\"']+", str(ev))
            if m:
                url = _d8_url(m.group(0))
    hostname = _d8_hostname(meta.get("hostname") or meta.get("host") or meta.get("domain"))
    if not hostname and url:
        hostname = _d8_hostname(url)
    asset_type = None
    asset_value = None
    if isinstance(getattr(finding, "asset_id", None), str) and getattr(finding, "asset_id"):
        asset_type = str(meta.get("asset_type") or "").strip().lower() or None
        asset_value = str(meta.get("asset_value") or "").strip() or None
    return {
        "rule_id": rule_id,
        "cve": _fp_cve(getattr(finding, "cve", None)) or _fp_cve(meta.get("cve")),
        "cwe": _fp_cwe(getattr(finding, "cwe", None)) or _fp_cwe(meta.get("cwe")),
        "normalized_title": _collapse_text(getattr(finding, "title", None)),
        "hostname": hostname,
        "url": url,
        "port": _d8_port(meta.get("port")),
        "parameter": _collapse_text(meta.get("parameter") or meta.get("param") or meta.get("field") or meta.get("input")),
        "file": _d8_file(meta.get("file") or meta.get("filepath") or meta.get("path") or meta.get("filename")),
        "line": line,
        "ip": _d8_ip(meta.get("ip") or meta.get("ipv4") or meta.get("ipv6") or meta.get("address")),
        "asset_type": asset_type,
        "asset_value": asset_value,
    }


def d8_fingerprint(payload: dict[str, Any]) -> str:
    """Canonical SHA-256 over the worker-identical fingerprint field set."""
    cleaned = {k: payload.get(k) for k in _FINGERPRINT_FIELDS if payload.get(k) is not None}
    serialized = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def d8_baseline_fingerprint(finding) -> tuple[str, dict[str, Any]]:
    """Baseline fingerprint for a finding + the canonical input (for audit)."""
    canonical = d8_finding_input(finding)
    return d8_fingerprint(canonical), canonical


def evaluate_retest_verification(
    baseline_fingerprint: str | None,
    detected_fingerprints: list[str] | set[str] | tuple[str, ...] | None,
    scan_status: str | None,
    parser_ok: bool = True,
    completeness: str = "complete",
) -> tuple[str, str]:
    """Deterministic verification decision.

    Returns (result, note) with result in {passed, failed, error}.
    Scanner/parser failure or incomplete evidence is NEVER passed:
    absence of authoritative evidence is not proof of remediation.
    """
    detected = set(detected_fingerprints or [])
    if (scan_status or "").strip().lower() != "completed":
        return ("error", "Verification could not be established because the verification scan did not complete.")
    if not parser_ok:
        return ("error", "Verification could not be established because parser output was not authoritative.")
    if (completeness or "").strip().lower() != "complete":
        return ("error", "Verification could not be established because verification evidence was incomplete.")
    if baseline_fingerprint and baseline_fingerprint in detected:
        return ("failed", "Original finding fingerprint was detected again during verification.")
    return ("passed", "Original finding fingerprint was not detected during the completed verification scan.")
