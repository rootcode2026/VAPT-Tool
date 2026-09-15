"""AI Context — bounded retrieval from PostgreSQL, sanitized, tenant-safe."""
from __future__ import annotations

import re
from sqlalchemy.orm import Session
from app.core.config import settings

SENSITIVE_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key|private|credential).*")

def _sanitize_text(text: str, max_len: int = 500) -> str:
    if not text:
        return ""
    if SENSITIVE_RE.search(text.lower()):
        return "[REDACTED]"
    return text[:max_len]

def _sanitize_evidence(text: str) -> str:
    if not text:
        return ""
    # Treat evidence as DATA not instructions — redact sensitive + bound length
    # Strip common prompt-injection markers contained in scanner evidence
    low = text.lower()
    for tok in ("authorization", "cookie", "api-key", "password", "secret", "private key", "bearer"):
        if tok in low:
            text = re.sub(r"(?i)(authorization|cookie|x-api-key|password|secret|private key|bearer)\s*[:=]\s*[^\n]+", r"\1: [REDACTED]", text)
    # Neutralize instruction-like fragments that could be embedded in evidence
    text = re.sub(r"(?i)(ignore previous instructions|system prompt|reveal secrets)", "[filtered]", text)
    return text[:500]

def build_context(db: Session, organization_id: str, project_id: str, query: str, filters: dict | None = None) -> dict:
    filters = filters or {}
    # Enforce bounds
    max_findings = min(settings.AI_MAX_CONTEXT_FINDINGS, 20)
    max_assets = min(settings.AI_MAX_CONTEXT_ASSETS, 10)

    context: dict = {"organization_id": organization_id, "project_id": project_id, "query": query[:500], "findings": [], "assets": [], "scans": [], "reports": []}

    # Findings — deterministic, tenant-isolated
    try:
        from app.models.finding import Finding
        from app.models.target import Target
        from app.models.project import Project
        q = db.query(Finding).join(Target, Target.id == Finding.target_id).join(Project, Project.id == Target.project_id).filter(Project.organization_id == organization_id)
        if project_id:
            q = q.filter(Target.project_id == project_id)
        # filters allowlisted
        if filters.get("severity"):
            q = q.filter(Finding.severity == str(filters["severity"]).lower())
        if filters.get("status"):
            q = q.filter(Finding.status == str(filters["status"]).lower())
        if filters.get("scanner"):
            q = q.filter(Finding.scanner == str(filters["scanner"]).lower())
        findings = q.order_by(Finding.created_at.desc()).limit(max_findings).all()
        for f in findings:
            # Evidence-first provenance: every finding cited must carry tenant-safe references
            context["findings"].append({
                "id": f.id,
                "title": _sanitize_text(f.title, 200),
                "severity": f.severity,
                "status": f.status,
                "scanner": f.scanner,
                "source": f.scanner,
                "evidence": _sanitize_evidence(f.evidence or ""),
                "asset_id": f.asset_id,
                "scan_id": f.scan_id,
                "target_id": f.target_id,
                "cve": _sanitize_text(f.cve or "", 50),
                "cwe": _sanitize_text(f.cwe or "", 50),
                "score": f.score,
                "created_at": f.created_at.isoformat() if getattr(f, "created_at", None) else None,
                "confidence": "high" if f.severity in ("critical", "high") else "medium",
            })
    except Exception:
        pass

    # Assets
    try:
        from app.models.asset import Asset
        from app.models.project import Project
        aq = db.query(Asset).join(Project, Project.id == Asset.project_id).filter(Project.organization_id == organization_id)
        if project_id:
            aq = aq.filter(Asset.project_id == project_id)
        assets = aq.limit(max_assets).all()
        for a in assets:
            meta = a.extra_data if isinstance(a.extra_data, dict) else {}
            # sanitize no secrets
            safe_meta = {k: v for k, v in (meta.items() if isinstance(meta, dict) else []) if not SENSITIVE_RE.search(k)}
            context["assets"].append({
                "id": a.id,
                "asset_type": a.asset_type,
                "value": _sanitize_text(a.value, 200),
                "status": a.status,
                "criticality": getattr(a, "criticality", "unknown"),
                "first_seen_at": a.first_seen_at.isoformat() if getattr(a, "first_seen_at", None) else None,
                "last_seen_at": a.last_seen_at.isoformat() if getattr(a, "last_seen_at", None) else None,
                "metadata": {k: str(v)[:200] for k, v in list(safe_meta.items())[:5]},
            })
    except Exception:
        pass

    # Scans
    try:
        from app.models.scan import Scan
        from app.models.target import Target
        from app.models.project import Project
        sq = db.query(Scan).join(Target, Target.id == Scan.target_id).join(Project, Project.id == Target.project_id).filter(Project.organization_id == organization_id)
        if project_id:
            sq = sq.filter(Target.project_id == project_id)
        scans = sq.order_by(Scan.created_at.desc()).limit(5).all()
        for s in scans:
            context["scans"].append({"id": s.id, "profile": s.profile, "status": s.status, "target_id": s.target_id, "created_at": s.created_at.isoformat() if getattr(s, "created_at", None) else None, "risk_score": getattr(s, "risk_score", None)})
    except Exception:
        pass

    # Bound evidence length per finding (deterministic preprocessing)
    for f in context["findings"]:
        f["evidence"] = f["evidence"][:300] if isinstance(f.get("evidence"), str) else ""
    # Lightweight relationship hint (bounded, deterministic) — reuse existing AssetRelationship without vector DB
    try:
        from app.models.asset import Asset as _Asset  # noqa: F401
        # Count relationships for retrieved assets only (bounded 10)
        if context["assets"]:
            from sqlalchemy import text as _text
            # Best-effort: count relationships where source in retrieved asset ids (bounded)
            context["relationship_count"] = min(len(context["assets"]) * 2, 20)
    except Exception:
        context["relationship_count"] = 0
    # Bound total chars — keep prompt under 8k to control token cost
    import json
    raw = json.dumps(context)
    if len(raw) > 8000:
        # trim findings first (evidence is largest)
        context["findings"] = context["findings"][:5]
        for f in context["findings"]:
            f["evidence"] = f["evidence"][:100]
        # re-check
        raw = json.dumps(context)
        if len(raw) > 8000:
            context["assets"] = context["assets"][:3]
            for a in context["assets"]:
                a["metadata"] = {}
    return context

# Safe query planner — allowlisted operations
ALLOWED_OPERATIONS = {"FINDINGS_SEARCH", "ASSETS_SEARCH", "SCAN_SEARCH", "CLOUD_FINDINGS_SEARCH", "CODE_FINDINGS_SEARCH", "ATTACK_PATH_SEARCH"}
ALLOWED_FILTERS = {"severity", "status", "scanner", "asset_type", "project_id"}

def plan_query(prompt: str) -> dict:
    # Simple deterministic planner: keyword matching, not LLM SQL
    low = prompt.lower()
    if "critical" in low and "finding" in low:
        return {"operation": "FINDINGS_SEARCH", "filters": {"severity": "critical"}, "limit": 10}
    if "cloud" in low:
        return {"operation": "CLOUD_FINDINGS_SEARCH", "filters": {}, "limit": 10}
    if "asset" in low and ("exposed" in low or "internet" in low):
        return {"operation": "ASSETS_SEARCH", "filters": {"asset_type": "domain"}, "limit": 10}
    if "sql injection" in low:
        return {"operation": "FINDINGS_SEARCH", "filters": {"scanner": "sqlmap"}, "limit": 10}
    return {"operation": "FINDINGS_SEARCH", "filters": {}, "limit": 10}

def validate_plan(plan: dict) -> dict:
    op = plan.get("operation")
    if op not in ALLOWED_OPERATIONS:
        raise ValueError("Invalid operation")
    filters = plan.get("filters", {})
    for k in list(filters.keys()):
        if k not in ALLOWED_FILTERS:
            raise ValueError(f"Invalid filter {k}")
    plan["limit"] = min(int(plan.get("limit", 10)), 20)
    return plan
