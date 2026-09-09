"""Alerting (D3) — D2 change events to durable deduplicated alerts, worker side.

Flow: D2 persists ``monitoring_change_events`` -> this evaluator (triggered
from ``finalize_monitoring_run`` after D2 commits) maps selected events to
alerts under a minimal project-scoped policy -> alerts persisted with
deterministic ``dedup_key`` UNIQUE + ``ON CONFLICT DO NOTHING``.

D2 -> D3 mapping (documented, deterministic):
- FINDING_CREATED severity critical/high -> NEW_CRITICAL/HIGH_FINDING
- FINDING_REOPENED severity critical/high -> CRITICAL/HIGH_FINDING_REOPENED
- FINDING_SEVERITY_CHANGED escalated to critical/high -> NEW_CRITICAL/HIGH_FINDING
- ASSET_CREATED of exposure-relevant type -> HIGH_ASSET_EXPOSURE
- ASSET_CREATED of other types -> SECURITY_RELEVANT_ASSET_CHANGE
- RELATIONSHIP_CREATED type=exposes on sensitive service/port ->
  CRITICAL_ASSET_EXPOSURE (documented heuristic, see _SENSITIVE_PORTS)
- RELATIONSHIP_CREATED type in {exposes, serves, points_to} ->
  HIGH_ASSET_EXPOSURE
- RELATIONSHIP_CREATED of other types -> SECURITY_RELEVANT_RELATIONSHIP_CHANGE
- ASSET_METADATA_CHANGED -> SECURITY_RELEVANT_ASSET_CHANGE
- FINDING_STATUS_CHANGED (non-reopen) -> no alert (status churn alone)
- Retractions (RESOLVED/REMOVED) -> resolve matching open alerts, never
  create alerts. Absence events only exist on complete observations (D2
  guarantee), so failed scanners can never fabricate resolutions.

Severity: finding alerts take the finding severity; HIGH_ASSET_EXPOSURE is
high; CRITICAL_ASSET_EXPOSURE is critical; SECURITY_RELEVANT_* is medium.
``min_severity`` gates finding-sourced alerts; asset/relationship alerts
are gated by their category toggles.

Deduplication vs idempotency: the same change event reprocessed bumps
``event_count``/``last_seen_at`` on the existing alert (same dedup_key);
equivalent later events do the same. A resolved alert that recurs is
reopened in place (history preserved, never silently mutated).

Failure handling: evaluation runs after D2 commits, in its own
transaction; errors record bounded ``alert_error`` on the run. D2 events,
runs, scans, findings and assets are never rolled back and no retry
framework is introduced.

Privacy: titles/descriptions are deterministic templates over bounded
D2 summaries; raw scanner output, bodies, code, credentials and customer
payloads are never stored.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

# Canonical D3 alert taxonomy (small by design).
NEW_CRITICAL_FINDING = "NEW_CRITICAL_FINDING"
NEW_HIGH_FINDING = "NEW_HIGH_FINDING"
CRITICAL_FINDING_REOPENED = "CRITICAL_FINDING_REOPENED"
HIGH_FINDING_REOPENED = "HIGH_FINDING_REOPENED"
CRITICAL_ASSET_EXPOSURE = "CRITICAL_ASSET_EXPOSURE"
HIGH_ASSET_EXPOSURE = "HIGH_ASSET_EXPOSURE"
SECURITY_RELEVANT_ASSET_CHANGE = "SECURITY_RELEVANT_ASSET_CHANGE"
SECURITY_RELEVANT_RELATIONSHIP_CHANGE = "SECURITY_RELEVANT_RELATIONSHIP_CHANGE"

ALERT_TYPES = frozenset(
    {
        NEW_CRITICAL_FINDING,
        NEW_HIGH_FINDING,
        CRITICAL_FINDING_REOPENED,
        HIGH_FINDING_REOPENED,
        CRITICAL_ASSET_EXPOSURE,
        HIGH_ASSET_EXPOSURE,
        SECURITY_RELEVANT_ASSET_CHANGE,
        SECURITY_RELEVANT_RELATIONSHIP_CHANGE,
    }
)

ALERT_OPEN = "open"
ALERT_ACKNOWLEDGED = "acknowledged"
ALERT_RESOLVED = "resolved"
ALERT_ACTIVE = (ALERT_OPEN, ALERT_ACKNOWLEDGED)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Asset types considered network-reachable/visible for exposure alerts.
EXPOSURE_ASSET_TYPES = frozenset(
    {"domain", "url", "web_host", "web_site", "ip", "ipv6", "tls_endpoint"}
)

# Relationship types indicating reachable exposure.
EXPOSURE_RELATIONSHIP_TYPES = frozenset({"exposes", "serves", "points_to"})

# Destination ports treated as sensitive for the critical-exposure
# heuristic: remote-admin and data-store services whose new exposure is
# operationally critical. Documented heuristic, not a vulnerability verdict.
_SENSITIVE_PORTS = frozenset(
    {
        "21", "22", "23", "25", "110", "139", "143", "445", "1433", "1521",
        "3306", "3389", "5432", "5433", "6379", "27017", "9200", "5601",
        "8080", "8443", "8000", "5000", "3000", "9000", "9090",
    }
)

_MAX_EVENTS_PER_RUN = 1000
_TITLE_CAP = 500
_DESC_CAP = 2000


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_json(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return None


def _canon_severity(value) -> str:
    s = str(value or "info").strip().lower()
    if s == "informational":
        return "info"
    return s if s in _SEVERITY_RANK else "info"


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(_canon_severity(severity), 0)


def _short(value, cap: int = 200) -> str:
    s = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    s = str(s or "")
    return s[:cap] if len(s) > cap else s


def _dedup_key(project_id: str, alert_type: str, object_key: str) -> str:
    raw = "\x1f".join([str(project_id), str(alert_type), str(object_key)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _asset_object_key(state: dict | None) -> str | None:
    if not isinstance(state, dict):
        return None
    atype, value = state.get("asset_type"), state.get("value")
    if not atype or not value:
        return None
    return f"{atype}\x1f{value}"


def _rel_object_key(state: dict | None) -> str | None:
    if not isinstance(state, dict):
        return None
    parts = [state.get("source_type"), state.get("source_value"),
             state.get("target_type"), state.get("target_value"),
             state.get("relationship_type")]
    if not all(parts):
        return None
    return "\x1f".join(str(p) for p in parts)


def _rel_exposes_sensitive(state: dict | None) -> bool:
    """Critical-exposure heuristic: an `exposes` edge onto a service or a
    sensitive port. Deterministic and documented; not a verdict."""
    if not isinstance(state, dict):
        return False
    if str(state.get("relationship_type") or "") != "exposes":
        return False
    ttype = str(state.get("target_type") or "")
    tvalue = str(state.get("target_value") or "")
    if ttype == "service":
        return True
    if ttype == "port":
        port = tvalue.split(":")[-1].strip()
        return port in _SENSITIVE_PORTS
    return False


def _default_policy() -> dict:
    return {
        "enabled": True,
        "min_severity": "high",
        "alert_critical_findings": True,
        "alert_high_findings": True,
        "alert_reopened": True,
        "alert_asset_exposure": True,
        "alert_relationships": False,
        "alert_metadata_changes": False,
    }


def _policy_from_row(row) -> dict:
    if row is None:
        return _default_policy()
    try:
        get = row.get if hasattr(row, "get") else (lambda k: row[k])
    except Exception:
        return _default_policy()

    def _bool(key, default):
        try:
            v = get(key)
        except Exception:
            return default
        if v is None:
            return default
        if isinstance(v, bool):
            return v
        return str(v).strip().lower() not in ("0", "false", "no", "off", "")

    try:
        min_sev = str(get("min_severity") or "high").strip().lower()
    except Exception:
        min_sev = "high"
    if min_sev not in _SEVERITY_RANK:
        min_sev = "high"
    return {
        "enabled": _bool("enabled", True),
        "min_severity": min_sev,
        "alert_critical_findings": _bool("alert_critical_findings", True),
        "alert_high_findings": _bool("alert_high_findings", True),
        "alert_reopened": _bool("alert_reopened", True),
        "alert_asset_exposure": _bool("alert_asset_exposure", True),
        "alert_relationships": _bool("alert_relationships", False),
        "alert_metadata_changes": _bool("alert_metadata_changes", False),
    }


def map_event_to_alerts(event: dict, policy: dict) -> list[dict]:
    """Pure mapping from one D2 change event to alert candidates.

    Returns [] when policy suppresses the event. Candidates carry everything
    the upsert needs; no DB access here (unit-testable, deterministic).
    """
    if not policy.get("enabled", True):
        return []
    ctype = str(event.get("change_type") or "")
    curr = _parse_json(event.get("current_state")) or {}
    prev = _parse_json(event.get("previous_state")) or {}
    if not isinstance(curr, dict):
        curr = {}
    if not isinstance(prev, dict):
        prev = {}

    if ctype == "FINDING_CREATED":
        sev = _canon_severity(curr.get("severity"))
        if _rank(sev) < _rank(policy.get("min_severity", "high")):
            return []
        if sev == "critical" and policy.get("alert_critical_findings", True):
            return [_finding_candidate(event, NEW_CRITICAL_FINDING, "critical", curr)]
        if sev == "high" and policy.get("alert_high_findings", True):
            return [_finding_candidate(event, NEW_HIGH_FINDING, "high", curr)]
        return []

    if ctype == "FINDING_REOPENED":
        if not policy.get("alert_reopened", True):
            return []
        sev = _canon_severity(curr.get("severity"))
        if _rank(sev) < _rank(policy.get("min_severity", "high")):
            return []
        if sev == "critical" and policy.get("alert_critical_findings", True):
            return [_finding_candidate(event, CRITICAL_FINDING_REOPENED, "critical", curr)]
        if sev == "high" and policy.get("alert_high_findings", True):
            return [_finding_candidate(event, HIGH_FINDING_REOPENED, "high", curr)]
        return []

    if ctype == "FINDING_SEVERITY_CHANGED":
        sev = _canon_severity(curr.get("severity"))
        if _rank(sev) < _rank(policy.get("min_severity", "high")):
            return []
        if sev == "critical" and policy.get("alert_critical_findings", True):
            return [_finding_candidate(event, NEW_CRITICAL_FINDING, "critical", curr)]
        if sev == "high" and policy.get("alert_high_findings", True):
            return [_finding_candidate(event, NEW_HIGH_FINDING, "high", curr)]
        return []

    if ctype == "ASSET_CREATED":
        if not policy.get("alert_asset_exposure", True):
            return []
        atype = str(curr.get("asset_type") or "")
        value = str(curr.get("value") or "")
        if not atype or not value:
            return []
        if atype in EXPOSURE_ASSET_TYPES:
            return [_asset_candidate(event, HIGH_ASSET_EXPOSURE, "high", curr,
                                     f"New externally visible asset detected: {value}")]
        return [_asset_candidate(event, SECURITY_RELEVANT_ASSET_CHANGE, "medium", curr,
                                 f"New asset observed: {value}")]

    if ctype == "ASSET_METADATA_CHANGED":
        if not policy.get("alert_metadata_changes", False):
            return []
        value = str(curr.get("value") or curr.get("asset_type") or "asset")
        return [_asset_candidate(event, SECURITY_RELEVANT_ASSET_CHANGE, "medium", curr,
                                 f"Security-relevant asset change on {value}")]

    if ctype == "RELATIONSHIP_CREATED":
        rtype = str(curr.get("relationship_type") or "")
        if _rel_exposes_sensitive(curr) and policy.get("alert_asset_exposure", True):
            return [_rel_candidate(event, CRITICAL_ASSET_EXPOSURE, "critical", curr,
                                   "New critical asset exposure detected")]
        if rtype in EXPOSURE_RELATIONSHIP_TYPES and policy.get("alert_asset_exposure", True):
            return [_rel_candidate(event, HIGH_ASSET_EXPOSURE, "high", curr,
                                   "New externally reachable exposure detected")]
        if policy.get("alert_relationships", False):
            return [_rel_candidate(event, SECURITY_RELEVANT_RELATIONSHIP_CHANGE, "medium", curr,
                                   "Security-relevant relationship change detected")]
        return []

    # FINDING_STATUS_CHANGED (non-reopen), retractions and anything else:
    # never create alerts. Retractions drive resolution, handled separately.
    return []


def _finding_candidate(event: dict, alert_type: str, severity: str, curr: dict) -> dict:
    fp = curr.get("fingerprint") or ""
    title = str(curr.get("title") or "Security finding")[:_TITLE_CAP]
    label = "Critical vulnerability detected" if severity == "critical" else "High severity finding detected"
    if "REOPENED" in alert_type:
        label = ("Critical finding reopened" if severity == "critical"
                 else "High severity finding reopened")
    return {
        "alert_type": alert_type,
        "severity": severity,
        "title": f"{label}: {title}"[:_TITLE_CAP],
        "description": (
            f"{label} on scan {event.get('scan_id') or 'unknown'} "
            f"(monitoring run {event.get('curr_run_id') or 'unknown'}). "
            f"Status: {curr.get('status') or 'unknown'}."
        )[:_DESC_CAP],
        "object_key": f"finding\x1f{fp}",
        "finding_fingerprint": fp or None,
        "finding_id": event.get("finding_id"),
        "asset_id": event.get("asset_id"),
        "asset_key": None,
        "rel_key": None,
    }


def _asset_candidate(event: dict, alert_type: str, severity: str, curr: dict, title: str) -> dict:
    akey = _asset_object_key(curr)
    return {
        "alert_type": alert_type,
        "severity": severity,
        "title": title[:_TITLE_CAP],
        "description": (
            f"Asset {curr.get('asset_type')}/{curr.get('value')} observed in "
            f"monitoring run {event.get('curr_run_id') or 'unknown'} "
            f"via {(event.get('scanners') or ['unknown'])[0] if isinstance(event.get('scanners'), list) and event.get('scanners') else 'unknown'}."
        )[:_DESC_CAP],
        "object_key": f"asset\x1f{akey}" if akey else None,
        "finding_fingerprint": None,
        "finding_id": None,
        "asset_id": event.get("asset_id"),
        "asset_key": akey,
        "rel_key": None,
    }


def _rel_candidate(event: dict, alert_type: str, severity: str, curr: dict, title: str) -> dict:
    rkey = _rel_object_key(curr)
    src = f"{curr.get('source_type')}/{curr.get('source_value')}"
    dst = f"{curr.get('target_type')}/{curr.get('target_value')}"
    return {
        "alert_type": alert_type,
        "severity": severity,
        "title": f"{title}: {src} -> {dst} ({curr.get('relationship_type')})"[:_TITLE_CAP],
        "description": (
            f"Relationship {curr.get('relationship_type')} observed between {src} and {dst} "
            f"in monitoring run {event.get('curr_run_id') or 'unknown'}."
        )[:_DESC_CAP],
        "object_key": f"rel\x1f{rkey}" if rkey else None,
        "finding_fingerprint": None,
        "finding_id": None,
        "asset_id": None,
        "asset_key": None,
        "rel_key": rkey,
    }


def _resolution_matches(event: dict) -> dict | None:
    """Return resolution matchers for retraction events, else None."""
    ctype = str(event.get("change_type") or "")
    if ctype == "FINDING_RESOLVED":
        prev = _parse_json(event.get("previous_state")) or {}
        fp = prev.get("fingerprint") if isinstance(prev, dict) else None
        if not fp:
            return None
        return {"finding_fingerprint": fp}
    if ctype == "ASSET_REMOVED":
        prev = _parse_json(event.get("previous_state")) or {}
        akey = _asset_object_key(prev if isinstance(prev, dict) else None)
        if not akey:
            return None
        return {"asset_key": akey}
    if ctype == "RELATIONSHIP_REMOVED":
        prev = _parse_json(event.get("previous_state")) or {}
        rkey = _rel_object_key(prev if isinstance(prev, dict) else None)
        if not rkey:
            return None
        return {"rel_key": rkey}
    return None


# ---------------------------------------------------------------------------
# Evaluation (transactional, idempotent, never raises)
# ---------------------------------------------------------------------------


def _load_policy(db, project_id: str) -> dict:
    try:
        row = (
            db.execute(
                text("SELECT enabled, min_severity, alert_critical_findings, alert_high_findings, "
                     "alert_reopened, alert_asset_exposure, alert_relationships, "
                     "alert_metadata_changes FROM alert_policies WHERE project_id = :pid"),
                {"pid": project_id},
            )
            .mappings()
            .first()
        )
    except Exception:
        row = None
    if row is None:
        try:
            db.execute(
                text("INSERT INTO alert_policies (project_id) VALUES (:pid) "
                     "ON CONFLICT (project_id) DO NOTHING"),
                {"pid": project_id},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        return _default_policy()
    return _policy_from_row(row)


def _load_run_events(db, run_id: str) -> list:
    try:
        rows = (
            db.execute(
                text(
                    "SELECT id, project_id, monitoring_config_id, prev_run_id, curr_run_id, "
                    "change_type, asset_id, finding_id, scan_id, previous_state, current_state, "
                    "scanners, scan_ids, completeness, detected_at, metadata AS extra_data "
                    "FROM monitoring_change_events WHERE curr_run_id = :rid "
                    "ORDER BY detected_at, id LIMIT :limit"
                ),
                {"rid": run_id, "limit": _MAX_EVENTS_PER_RUN},
            )
            .mappings()
            .all()
        )
    except Exception:
        return []
    return [dict(r) for r in rows]


def _upsert_alert(db, project_id, org_id, config_id, candidate: dict, event: dict, now: datetime) -> bool:
    """Insert or bump exactly one alert for a candidate. Returns True when a
    NEW alert row was created (vs deduplicated/reopened). Never raises."""
    object_key = candidate.get("object_key")
    if not object_key:
        return False
    key = _dedup_key(project_id, candidate["alert_type"], object_key)
    scanners = _parse_json(event.get("scanners")) or []
    scan_ids = _parse_json(event.get("scan_ids")) or []
    meta = {
        "monitoring_config_id": config_id,
        "monitoring_run_id": event.get("curr_run_id"),
        "prev_run_id": event.get("prev_run_id"),
        "source_change_event_id": event.get("id"),
        "scanners": scanners if isinstance(scanners, list) else [],
        "scan_ids": scan_ids if isinstance(scan_ids, list) else [],
        "completeness": event.get("completeness") or "complete",
    }
    if candidate.get("rel_key"):
        meta["rel_key"] = candidate["rel_key"]
    try:
        res = db.execute(
            text(
                "INSERT INTO alerts (id, organization_id, project_id, monitoring_config_id, "
                "alert_type, severity, status, title, description, source_change_event_id, "
                "source_finding_id, source_asset_id, finding_fingerprint, asset_key, "
                "monitoring_run_id, first_seen_at, last_seen_at, event_count, dedup_key, metadata) "
                "VALUES (:id, :oid, :pid, :cid, :atype, :sev, 'open', :title, :desc, :evid, "
                ":fid, :aid, :fp, :akey, :rid, :now, :now, 1, :dkey, :meta) "
                "ON CONFLICT (dedup_key) DO NOTHING"
            ),
            {
                "id": str(uuid.uuid4()),
                "oid": org_id,
                "pid": project_id,
                "cid": config_id,
                "atype": candidate["alert_type"],
                "sev": candidate["severity"],
                "title": candidate["title"],
                "desc": candidate.get("description"),
                "evid": event.get("id"),
                "fid": candidate.get("finding_id"),
                "aid": candidate.get("asset_id"),
                "fp": candidate.get("finding_fingerprint"),
                "akey": candidate.get("asset_key"),
                "rid": event.get("curr_run_id"),
                "now": now,
                "dkey": key,
                "meta": json.dumps(meta),
            },
        )
        try:
            inserted = bool(res.rowcount)
        except Exception:
            inserted = True
        if inserted:
            return True
    except Exception:
        # Persistence failure (e.g. table unavailable): propagate so the
        # caller can record a bounded evaluation failure instead of
        # silently dropping the event.
        raise
    # Deduplicated (or raced): bump the existing row; reopen if resolved.
    try:
        row = (
            db.execute(
                text("SELECT id, status FROM alerts WHERE dedup_key = :k"),
                {"k": key},
            )
            .mappings()
            .first()
        )
        if not row:
            return False
        if row["status"] == ALERT_RESOLVED:
            db.execute(
                text(
                    "UPDATE alerts SET status = 'open', resolved_at = NULL, resolved_by = NULL, "
                    "last_seen_at = :now, event_count = event_count + 1, "
                    "source_change_event_id = :evid, monitoring_run_id = :rid, "
                    "metadata = :meta WHERE id = :id"
                ),
                {"now": now, "evid": event.get("id"), "rid": event.get("curr_run_id"),
                 "meta": json.dumps(meta), "id": row["id"]},
            )
        elif row["status"] in ALERT_ACTIVE:
            db.execute(
                text(
                    "UPDATE alerts SET last_seen_at = :now, event_count = event_count + 1, "
                    "source_change_event_id = :evid, monitoring_run_id = :rid, "
                    "metadata = :meta WHERE id = :id"
                ),
                {"now": now, "evid": event.get("id"), "rid": event.get("curr_run_id"),
                 "meta": json.dumps(meta), "id": row["id"]},
            )
    except Exception:
        pass
    return False


def _resolve_matching(db, project_id: str, match: dict, event: dict, now: datetime) -> int:
    """Resolve open/acknowledged alerts matching a retraction. Returns count."""
    clauses = ["project_id = :pid", "status IN ('open', 'acknowledged')"]
    args: dict = {"pid": project_id, "now": now}
    if "finding_fingerprint" in match:
        clauses.append("finding_fingerprint = :fp")
        args["fp"] = match["finding_fingerprint"]
    elif "asset_key" in match:
        clauses.append("asset_key = :ak")
        args["ak"] = match["asset_key"]
    elif "rel_key" in match:
        # rel_key lives inside the bounded metadata JSON (no dedicated
        # column); match the full canonical key as a substring, which is
        # effectively exact (NUL-separated source/value/type tuple).
        # CAST keeps this valid on both PostgreSQL (JSONB) and SQLite (TEXT).
        clauses.append("CAST(metadata AS TEXT) LIKE :rk")
        args["rk"] = f"%{match['rel_key']}%"
    else:
        return 0
    try:
        res = db.execute(
            text(
                f"UPDATE alerts SET status = 'resolved', resolved_at = :now, resolved_by = NULL "
                f"WHERE {' AND '.join(clauses)}"
            ),
            args,
        )
        try:
            return int(res.rowcount or 0)
        except Exception:
            return 0
    except Exception:
        return 0


def evaluate_run_alerts(db, run_id: str) -> dict:
    """Evaluate one run's durable D2 events into alerts.

    Claims the run via alert_status pending->processing (exactly one
    winner), maps events under the project policy, upserts alerts and
    applies resolutions. Returns a bounded summary. Never raises.
    """
    summary: dict = {"run_id": run_id, "alert_status": "unknown", "alerts_created": 0}
    try:
        run = (
            db.execute(
                text(
                    "SELECT id, monitoring_config_id, organization_id, project_id, status, "
                    "alert_status FROM monitoring_runs WHERE id = :rid"
                ),
                {"rid": run_id},
            )
            .mappings()
            .first()
        )
        if not run:
            summary["alert_status"] = "skipped"
            return summary
        if run["status"] == "failed":
            if (run.get("alert_status") or "") == "pending":
                db.execute(
                    text("UPDATE monitoring_runs SET alert_status = 'skipped' WHERE id = :rid"),
                    {"rid": run_id},
                )
                db.commit()
            summary["alert_status"] = "skipped"
            return summary
        if run["status"] not in ("completed", "partial"):
            summary["alert_status"] = "skipped"
            return summary
        claimed = db.execute(
            text(
                "UPDATE monitoring_runs SET alert_status = 'processing', alert_error = NULL "
                "WHERE id = :rid AND alert_status = 'pending'"
            ),
            {"rid": run_id},
        )
        try:
            claimed_count = claimed.rowcount
        except Exception:
            claimed_count = 1
        if not claimed_count:
            try:
                cur = (
                    db.execute(
                        text("SELECT alert_status FROM monitoring_runs WHERE id = :rid"),
                        {"rid": run_id},
                    ).fetchone()
                )
                summary["alert_status"] = cur[0] if cur else "unknown"
            except Exception:
                summary["alert_status"] = "unknown"
            try:
                db.rollback()
            except Exception:
                pass
            return summary
        try:
            return _evaluate_claimed_run(db, run, summary)
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                pass
            err = str(exc)[:500]
            try:
                db.execute(
                    text(
                        "UPDATE monitoring_runs SET alert_status = 'failed', alert_error = :err "
                        "WHERE id = :rid"
                    ),
                    {"err": err, "rid": run_id},
                )
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            summary["alert_status"] = "failed"
            summary["alert_error"] = err
            return summary
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        summary["alert_status"] = "failed"
        summary["alert_error"] = str(exc)[:500]
        return summary


def _evaluate_claimed_run(db, run, summary: dict) -> dict:
    run_id = run["id"]
    project_id = run["project_id"]
    now = _utcnow_naive()
    policy = _load_policy(db, project_id)
    events = _load_run_events(db, run_id)
    created = 0
    resolved = 0
    event_errors = 0
    for ev in events:
        try:
            for candidate in map_event_to_alerts(dict(ev), policy):
                if _upsert_alert(db, project_id, run["organization_id"],
                                 run["monitoring_config_id"], candidate, dict(ev), now):
                    created += 1
            match = _resolution_matches(dict(ev))
            if match:
                resolved += _resolve_matching(db, project_id, match, dict(ev), now)
        except Exception:
            event_errors += 1
            continue
    if events and created == 0 and resolved == 0 and event_errors == len(events):
        raise RuntimeError(f"alert evaluation failed for all {len(events)} events")
    db.execute(
        text(
            "UPDATE monitoring_runs SET alert_status = 'completed', alert_error = NULL, "
            "alerts_created = :n WHERE id = :rid"
        ),
        {"n": created, "rid": run_id},
    )
    db.commit()
    summary.update({"alert_status": "completed", "alerts_created": created, "resolved": resolved})
    return summary
