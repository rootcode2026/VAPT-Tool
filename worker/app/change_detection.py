"""Change Detection (D2) — run-level observation comparison, worker side.

Compares the CURRENT monitoring observation (assets / findings /
relationships linked to a run's scans) against the PREVIOUS TRUSTED
observation (one snapshot row per config) and records durable,
evidence-backed change records in ``monitoring_change_events``.

Baseline semantics (documented, deterministic):
- First COMPLETED run with usable content (>= 1 asset or finding)
  establishes the baseline and emits no events (no fake "created
  everything" history).
- COMPLETED runs compare fully (additive + absence events) and, on
  success, REPLACE the baseline.
- PARTIAL runs emit additive events only (created / metadata / status /
  severity), never removals/resolutions, and never replace the baseline.
- FAILED runs, empty observations, and partial runs without a baseline
  produce no events and never touch the baseline.
- Absence-based events (ASSET_REMOVED, FINDING_RESOLVED,
  RELATIONSHIP_REMOVED) require a COMPLETED current observation, so a
  failed scanner can never masquerade as disappearing infrastructure.

Identity rules (reused, never reinvented here):
- assets: canonical (asset_type, value) — never scan/run/timestamp bound.
- findings: existing ``fingerprint_finding`` (scanner- and version-
  independent); version/digest differences are provenance, never identity.
- relationships: canonical (source type/value, target type/value, type).

Idempotency & concurrency: runs carry ``change_status``
(pending/processing/completed/failed/skipped). Exactly one worker claims a
run via ``UPDATE ... WHERE change_status='pending'`` (rowcount decides);
events carry a deterministic ``event_key`` UNIQUE with ``ON CONFLICT DO
NOTHING``. Reprocessing is a no-op. No new locking infrastructure.

Failure handling: all errors are contained — a bounded ``change_error``
is recorded on the run; MonitoringRun/Scan/Finding/Asset/baseline rows
are never destroyed and no retry architecture is introduced.

Privacy: previous/current states are BOUNDED summaries (capped strings,
lists, depth; secret-adjacent keys dropped via the existing persistence
sanitizer). Raw scanner output, HTTP bodies, source code, credentials
and customer payloads are never stored.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import bindparam, text

from app.asset_intel.change_detection import VOLATILE_METADATA_KEYS
from app.services.finding_correlation.normalizer import fingerprint_finding

try:
    from app.persistence import sanitize_metadata as _sanitize_metadata
except Exception:  # pragma: no cover - defensive fallback
    _sanitize_metadata = None


# Canonical D2 change vocabulary (run-level; distinct from the per-scan
# new_asset/asset_disappeared/... vocabulary owned by asset_intel).
ASSET_CREATED = "ASSET_CREATED"
ASSET_REMOVED = "ASSET_REMOVED"
ASSET_METADATA_CHANGED = "ASSET_METADATA_CHANGED"
RELATIONSHIP_CREATED = "RELATIONSHIP_CREATED"
RELATIONSHIP_REMOVED = "RELATIONSHIP_REMOVED"
FINDING_CREATED = "FINDING_CREATED"
FINDING_RESOLVED = "FINDING_RESOLVED"
FINDING_REOPENED = "FINDING_REOPENED"
FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"
FINDING_SEVERITY_CHANGED = "FINDING_SEVERITY_CHANGED"

CHANGE_TYPES = frozenset(
    {
        ASSET_CREATED,
        ASSET_REMOVED,
        ASSET_METADATA_CHANGED,
        RELATIONSHIP_CREATED,
        RELATIONSHIP_REMOVED,
        FINDING_CREATED,
        FINDING_RESOLVED,
        FINDING_REOPENED,
        FINDING_STATUS_CHANGED,
        FINDING_SEVERITY_CHANGED,
    }
)

# Absence-based (retraction) events: only on COMPLETED observations.
RETRACTION_TYPES = frozenset({ASSET_REMOVED, FINDING_RESOLVED, RELATIONSHIP_REMOVED})

# Finding statuses considered resolved-ish / open-ish (mirrors the
# WORKFLOW_STATUSES vocabulary owned by backend/app/api/routes/findings.py).
RESOLVED_FINDING_STATUSES = frozenset(
    {"resolved", "closed", "remediated", "false_positive", "accepted_risk"}
)
OPEN_FINDING_STATUSES = frozenset(
    {
        "open",
        "detected",
        "triaged",
        "in_progress",
        "remediation_claimed",
        "ready_for_retest",
        "retesting",
        "reopened",
    }
)

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

# Metadata keys that must never influence identity or be stored in events.
D2_VOLATILE_KEYS = frozenset(
    {
        "monitoring_run_id",
        "correlation_id",
        "scan_ids",
        "run_id",
        "observed_at",
        "confidence",
        "first_seen_scan_id",
        "last_seen_scan_id",
    }
)

_SUMMARY_STR_CAP = 500
_SUMMARY_LIST_CAP = 50
_SUMMARY_DICT_CAP = 100
_SUMMARY_DEPTH = 4


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


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _summarize(value, depth: int = 0):
    """Bound arbitrary values for event states (no raw payloads)."""
    if depth > _SUMMARY_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:_SUMMARY_STR_CAP] if len(value) > _SUMMARY_STR_CAP else value
    if isinstance(value, (list, tuple)):
        return [_summarize(v, depth + 1) for v in list(value)[:_SUMMARY_LIST_CAP]]
    if isinstance(value, dict):
        out = {}
        for k in sorted(value.keys(), key=str)[:_SUMMARY_DICT_CAP]:
            out[str(k)[:100]] = _summarize(value[k], depth + 1)
        return out
    return str(value)[:_SUMMARY_STR_CAP]


def _clean_asset_metadata(metadata) -> dict:
    """Canonical comparable asset metadata: sanitized, volatile-free."""
    meta = _parse_json(metadata) or {}
    if not isinstance(meta, dict):
        return {}
    if _sanitize_metadata is not None:
        try:
            meta = _sanitize_metadata(meta) or {}
        except Exception:
            meta = {}
    if not isinstance(meta, dict):
        return {}
    drop = set(VOLATILE_METADATA_KEYS) | set(D2_VOLATILE_KEYS)
    cleaned = {k: v for k, v in meta.items() if k not in drop}
    return _sort_scalar_lists(cleaned)


def _sort_scalar_lists(value):
    """Recursively sort lists of pure scalars so ordering-only differences
    (e.g. ports ["80","443"] vs ["443","80"]) never create change events."""
    if isinstance(value, dict):
        return {k: _sort_scalar_lists(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = [_sort_scalar_lists(v) for v in value]
        if items and all(isinstance(x, (str, int, float, bool)) or x is None for x in items):
            try:
                return sorted(items, key=lambda x: (str(type(x)), str(x)))
            except Exception:
                return items
        return items
    return value


def _effective_severity(row: dict) -> str:
    raw = row.get("severity_override") or row.get("severity") or "info"
    s = str(raw).strip().lower()
    return _SEVERITY_MAP.get(s, "info")


def _finding_input(row: dict, asset_type=None, asset_value=None) -> dict:
    return {
        "scanner": row.get("scanner"),
        "title": row.get("title"),
        "severity": row.get("severity"),
        "score": row.get("score"),
        "cve": row.get("cve"),
        "cwe": row.get("cwe"),
        "status": row.get("status"),
        "metadata": _parse_json(row.get("metadata")) or {},
        "asset_type": asset_type,
        "asset_value": asset_value,
    }


def _is_sqlite(db) -> bool:
    try:
        return db.get_bind().dialect.name == "sqlite"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Observation loading (raw SQL, project-scoped via the run's own project)
# ---------------------------------------------------------------------------


def _load_run(db, run_id: str):
    return (
        db.execute(
            text(
                "SELECT id, monitoring_config_id, organization_id, project_id, "
                "status, scan_ids, change_status FROM monitoring_runs WHERE id = :rid"
            ),
            {"rid": run_id},
        )
        .mappings()
        .first()
    )


def _load_current_observation(db, project_id: str, scan_ids: list) -> dict:
    """Build the current observation from scan-linked rows.

    Assets via last_seen_scan_id, findings via scan_id, relationships via
    last_seen_scan_id — all constrained to this run's scans so overlapping
    activity from other runs cannot pollute the comparison.
    """
    obs: dict = {
        "assets": {},
        "findings": {},
        "relationships": {},
        "scanners": [],
        "versions": {},
        "scan_ids": list(scan_ids),
    }
    if not scan_ids:
        return obs

    asset_id_map: dict[str, tuple] = {}
    try:
        arows = (
            db.execute(
                text(
                    "SELECT id, asset_type, value FROM assets WHERE project_id = :pid"
                ),
                {"pid": project_id},
            )
            .mappings()
            .all()
        )
    except Exception:
        arows = []
    for r in arows:
        try:
            asset_id_map[r["id"]] = (r["asset_type"], r["value"])
        except Exception:
            continue

    try:
        assets = (
            db.execute(
                text(
                "SELECT id, asset_type, value, status, metadata, last_seen_scan_id "
                "FROM assets WHERE project_id = :pid AND last_seen_scan_id IN :sids"
                ).bindparams(bindparam("sids", expanding=True)),
                {"pid": project_id, "sids": list(scan_ids)},
            )
            .mappings()
            .all()
        )
    except Exception:
        assets = []
    for r in assets:
        try:
            atype, avalue = r["asset_type"], r["value"]
            if not atype or not avalue:
                continue
            cleaned = _clean_asset_metadata(r.get("metadata"))
            obs["assets"][(atype, avalue)] = {
                "asset_id": r["id"],
                "asset_type": atype,
                "value": avalue,
                "status": (r.get("status") or "unknown"),
                "scan_id": r.get("last_seen_scan_id"),
                "metadata": _summarize(cleaned),
                "metadata_digest": _digest(cleaned),
            }
        except Exception:
            continue

    try:
        findings = (
            db.execute(
                text(
                    "SELECT id, scanner, title, severity, severity_override, status, "
                    "cve, cwe, score, asset_id, metadata, target_id, scan_id "
                    "FROM findings WHERE scan_id IN :sids"
                ).bindparams(bindparam("sids", expanding=True)),
                {"sids": list(scan_ids)},
            )
            .mappings()
            .all()
        )
    except Exception:
        findings = []
    for r in findings:
        try:
            atype = aknown = None
            if r.get("asset_id") and r["asset_id"] in asset_id_map:
                atype, aknown = asset_id_map[r["asset_id"]]
            fp = fingerprint_finding(_finding_input(dict(r), atype, aknown))
            sev = _effective_severity(dict(r))
            obs["findings"][fp] = {
                "finding_id": r["id"],
                "fingerprint": fp,
                "title": str(r.get("title") or "")[:500],
                "severity": sev,
                "status": str(r.get("status") or "unknown"),
                "scanner": str(r.get("scanner") or "unknown"),
                "scan_id": r.get("scan_id"),
                "asset_id": r.get("asset_id"),
            }
        except Exception:
            continue

    try:
        rels = (
            db.execute(
                text(
                    "SELECT id, source_asset_id, target_asset_id, relationship_type, "
                    "last_seen_scan_id FROM asset_relationships "
                    "WHERE project_id = :pid AND last_seen_scan_id IN :sids"
                ).bindparams(bindparam("sids", expanding=True)),
                {"pid": project_id, "sids": list(scan_ids)},
            )
            .mappings()
            .all()
        )
    except Exception:
        rels = []
    for r in rels:
        try:
            src = asset_id_map.get(r["source_asset_id"])
            dst = asset_id_map.get(r["target_asset_id"])
            if not src or not dst:
                continue
            key = (src[0], src[1], dst[0], dst[1], r["relationship_type"])
            obs["relationships"][key] = {
                "relationship_id": r["id"],
                "source_type": src[0],
                "source_value": src[1],
                "target_type": dst[0],
                "target_value": dst[1],
                "relationship_type": r["relationship_type"],
                "scan_id": r.get("last_seen_scan_id"),
            }
        except Exception:
            continue

    try:
        srows = (
            db.execute(
                text(
                    "SELECT DISTINCT scanner FROM scan_results WHERE scan_id IN :sids"
                ).bindparams(bindparam("sids", expanding=True)),
                {"sids": list(scan_ids)},
            ).fetchall()
        )
        obs["scanners"] = sorted({str(x[0]) for x in srows if x and x[0]})
    except Exception:
        obs["scanners"] = []
    try:
        scans = (
            db.execute(
                text(
                    "SELECT scanner_version, scanner_image_digest, metadata FROM scans "
                    "WHERE id IN :sids"
                ).bindparams(bindparam("sids", expanding=True)),
                {"sids": list(scan_ids)},
            )
            .mappings()
            .all()
        )
        versions: dict = {}
        for s in scans:
            meta = _parse_json(s.get("metadata")) or {}
            if isinstance(meta, dict):
                for k, v in (meta.get("scanner_versions") or {}).items():
                    if isinstance(v, dict):
                        versions[str(k)] = {
                            "version": (v.get("version") if v.get("version") else None),
                            "digest": (v.get("digest") if v.get("digest") else None),
                        }
            if s.get("scanner_version") and "primary" not in versions:
                versions["primary"] = {
                    "version": s.get("scanner_version"),
                    "digest": s.get("scanner_image_digest"),
                }
        obs["versions"] = versions
    except Exception:
        obs["versions"] = {}
    return obs


def _load_baseline(db, config_id: str):
    return (
        db.execute(
            text(
                "SELECT config_id, run_id, observed_at, assets, findings, "
                "relationships, scanners FROM monitoring_observation_baselines "
                "WHERE config_id = :cid"
            ),
            {"cid": config_id},
        )
        .mappings()
        .first()
    )


def _store_baseline(db, config_id: str, run_id: str, obs: dict, now: datetime) -> None:
    payload = {
        "cid": config_id,
        "rid": run_id,
        "now": now,
        "assets": json.dumps(_snapshot_assets(obs["assets"])),
        "findings": json.dumps(_snapshot_findings(obs["findings"])),
        "relationships": json.dumps(_snapshot_relationships(obs["relationships"])),
        "scanners": json.dumps(
            {"scanners": obs.get("scanners") or [], "versions": obs.get("versions") or {}}
        ),
    }
    db.execute(
        text(
            "INSERT INTO monitoring_observation_baselines "
            "(config_id, run_id, observed_at, assets, findings, relationships, scanners) "
            "VALUES (:cid, :rid, :now, :assets, :findings, :relationships, :scanners) "
            "ON CONFLICT (config_id) DO UPDATE SET run_id = EXCLUDED.run_id, "
            "observed_at = EXCLUDED.observed_at, assets = EXCLUDED.assets, "
            "findings = EXCLUDED.findings, relationships = EXCLUDED.relationships, "
            "scanners = EXCLUDED.scanners"
        ),
        payload,
    )


def _snapshot_assets(assets: dict) -> dict:
    return {
        f"{t}\x00{v}": {
            "asset_type": t,
            "value": v,
            "status": a.get("status"),
            "metadata": a.get("metadata") or {},
            "metadata_digest": a.get("metadata_digest"),
        }
        for (t, v), a in assets.items()
    }


def _snapshot_findings(findings: dict) -> dict:
    return {
        fp: {
            "finding_id": f.get("finding_id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "status": f.get("status"),
            "scanner": f.get("scanner"),
        }
        for fp, f in findings.items()
    }


def _snapshot_relationships(relationships: dict) -> dict:
    return {
        "\x00".join(str(x) for x in key): dict(val)
        for key, val in relationships.items()
    }


# ---------------------------------------------------------------------------
# Pure comparison (deterministic; sorted output)
# ---------------------------------------------------------------------------


def compare_observations(baseline: dict, current: dict, complete: bool) -> list[dict]:
    """Diff a trusted baseline snapshot against the current observation.

    ``baseline`` uses snapshot shapes (string keys); ``current`` uses live
    observation shapes. Returns event dicts (without ids/keys) in stable
    sorted order. Additive-only when ``complete`` is False.
    """
    events: list[dict] = []
    base_assets = baseline.get("assets") or {}
    curr_assets: dict = {}
    for (t, v), a in (current.get("assets") or {}).items():
        curr_assets[f"{t}\x00{v}"] = a
    for key in sorted(curr_assets):
        if key not in base_assets:
            a = curr_assets[key]
            events.append(
                {
                    "change_type": ASSET_CREATED,
                    "asset_key": key,
                    "asset_id": a.get("asset_id"),
                    "finding_id": None,
                    "scan_id": a.get("scan_id"),
                    "previous_state": None,
                    "current_state": {
                        "asset_type": a.get("asset_type"),
                        "value": a.get("value"),
                        "status": a.get("status"),
                    },
                }
            )
        else:
            b = base_assets[key]
            a = curr_assets[key]
            if (b.get("metadata_digest") != a.get("metadata_digest")) or (
                (b.get("status") or "") != (a.get("status") or "")
                and a.get("status") not in ("unknown", None)
            ):
                events.append(
                    {
                        "change_type": ASSET_METADATA_CHANGED,
                        "asset_key": key,
                        "asset_id": a.get("asset_id") or b.get("asset_id"),
                        "finding_id": None,
                        "scan_id": a.get("scan_id"),
                        "previous_state": {
                            "asset_type": a.get("asset_type"),
                            "value": a.get("value"),
                            "status": b.get("status"),
                            "metadata": b.get("metadata") or {},
                        },
                        "current_state": {
                            "asset_type": a.get("asset_type"),
                            "value": a.get("value"),
                            "status": a.get("status"),
                            "metadata": a.get("metadata") or {},
                        },
                    }
                )
    if complete:
        for key in sorted(base_assets):
            if key not in curr_assets:
                b = base_assets[key]
                if str(b.get("status") or "active").lower() not in ("active", "stale"):
                    continue
                events.append(
                    {
                        "change_type": ASSET_REMOVED,
                        "asset_key": key,
                        "asset_id": b.get("asset_id"),
                        "finding_id": None,
                        "scan_id": None,
                        "previous_state": {
                            "asset_type": b.get("asset_type"),
                            "value": b.get("value"),
                            "status": b.get("status"),
                        },
                        "current_state": {
                            "asset_type": b.get("asset_type"),
                            "value": b.get("value"),
                            "status": "removed",
                        },
                    }
                )

    base_rels = baseline.get("relationships") or {}
    curr_rels: dict = {}
    for key, val in (current.get("relationships") or {}).items():
        skey = key if isinstance(key, str) else "\x00".join(str(x) for x in key)
        curr_rels[skey] = val
    for key in sorted(curr_rels):
        if key not in base_rels:
            r = curr_rels[key]
            events.append(
                {
                    "change_type": RELATIONSHIP_CREATED,
                    "asset_key": None,
                    "asset_id": None,
                    "finding_id": None,
                    "scan_id": r.get("scan_id"),
                    "previous_state": None,
                    "current_state": {
                        "source_type": r.get("source_type"),
                        "source_value": r.get("source_value"),
                        "target_type": r.get("target_type"),
                        "target_value": r.get("target_value"),
                        "relationship_type": r.get("relationship_type"),
                    },
                }
            )
    if complete:
        for key in sorted(base_rels):
            if key not in curr_rels:
                r = base_rels[key]
                events.append(
                    {
                        "change_type": RELATIONSHIP_REMOVED,
                        "asset_key": None,
                        "asset_id": None,
                        "finding_id": None,
                        "scan_id": None,
                        "previous_state": {
                            "source_type": r.get("source_type"),
                            "source_value": r.get("source_value"),
                            "target_type": r.get("target_type"),
                            "target_value": r.get("target_value"),
                            "relationship_type": r.get("relationship_type"),
                        },
                        "current_state": {
                            "source_type": r.get("source_type"),
                            "source_value": r.get("source_value"),
                            "target_type": r.get("target_type"),
                            "target_value": r.get("target_value"),
                            "relationship_type": r.get("relationship_type"),
                            "status": "removed",
                        },
                    }
                )

    base_f = baseline.get("findings") or {}
    curr_f = current.get("findings") or {}
    for fp in sorted(curr_f):
        c = curr_f[fp]
        if fp not in base_f:
            events.append(
                {
                    "change_type": FINDING_CREATED,
                    "asset_key": None,
                    "asset_id": c.get("asset_id"),
                    "finding_id": c.get("finding_id"),
                    "scan_id": c.get("scan_id"),
                    "previous_state": None,
                    "current_state": {
                        "fingerprint": fp,
                        "title": c.get("title"),
                        "severity": c.get("severity"),
                        "status": c.get("status"),
                        "scanner": c.get("scanner"),
                    },
                }
            )
            continue
        b = base_f[fp]
        b_status = str(b.get("status") or "unknown").lower()
        c_status = str(c.get("status") or "unknown").lower()
        if b_status in RESOLVED_FINDING_STATUSES and c_status in OPEN_FINDING_STATUSES:
            events.append(
                {
                    "change_type": FINDING_REOPENED,
                    "asset_key": None,
                    "asset_id": c.get("asset_id"),
                    "finding_id": c.get("finding_id"),
                    "scan_id": c.get("scan_id"),
                    "previous_state": {
                        "fingerprint": fp,
                        "title": b.get("title"),
                        "severity": b.get("severity"),
                        "status": b.get("status"),
                    },
                    "current_state": {
                        "fingerprint": fp,
                        "title": c.get("title"),
                        "severity": c.get("severity"),
                        "status": c.get("status"),
                    },
                }
            )
        elif b_status != c_status:
            events.append(
                {
                    "change_type": FINDING_STATUS_CHANGED,
                    "asset_key": None,
                    "asset_id": c.get("asset_id"),
                    "finding_id": c.get("finding_id"),
                    "scan_id": c.get("scan_id"),
                    "previous_state": {
                        "fingerprint": fp,
                        "title": c.get("title"),
                        "status": b.get("status"),
                    },
                    "current_state": {
                        "fingerprint": fp,
                        "title": c.get("title"),
                        "status": c.get("status"),
                    },
                }
            )
        if str(b.get("severity") or "") != str(c.get("severity") or ""):
            events.append(
                {
                    "change_type": FINDING_SEVERITY_CHANGED,
                    "asset_key": None,
                    "asset_id": c.get("asset_id"),
                    "finding_id": c.get("finding_id"),
                    "scan_id": c.get("scan_id"),
                    "previous_state": {"fingerprint": fp, "severity": b.get("severity")},
                    "current_state": {"fingerprint": fp, "severity": c.get("severity")},
                }
            )
    if complete:
        for fp in sorted(base_f):
            if fp not in curr_f:
                b = base_f[fp]
                if str(b.get("status") or "open").lower() not in OPEN_FINDING_STATUSES:
                    continue
                events.append(
                    {
                        "change_type": FINDING_RESOLVED,
                        "asset_key": None,
                        "asset_id": None,
                        "finding_id": None,
                        "scan_id": None,
                        "previous_state": {
                            "fingerprint": fp,
                            "title": b.get("title"),
                            "severity": b.get("severity"),
                            "status": b.get("status"),
                            "scanner": b.get("scanner"),
                        },
                        "current_state": {"fingerprint": fp, "status": "resolved"},
                    }
                )
    return events


def _event_key(project_id, config_id, prev_run_id, curr_run_id, event: dict) -> str:
    object_key = (
        event.get("asset_key")
        or event.get("finding_id")
        or (event.get("current_state") or {}).get("fingerprint")
        or (event.get("previous_state") or {}).get("fingerprint")
        or "-"
    )
    if isinstance(object_key, (dict, list)):
        object_key = _canonical_json(object_key)
    prev_digest = _digest(event.get("previous_state")) if event.get("previous_state") is not None else "-"
    curr_digest = _digest(event.get("current_state")) if event.get("current_state") is not None else "-"
    raw = "\x00".join(
        [
            str(project_id),
            str(config_id),
            str(prev_run_id or "-"),
            str(curr_run_id),
            str(event.get("change_type")),
            str(object_key),
            prev_digest,
            curr_digest,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Run processing (transactional, idempotent, never raises)
# ---------------------------------------------------------------------------


def process_run_changes(db, run_id: str) -> dict:
    """Compare one run's observation against the trusted baseline.

    Claims the run via change_status pending->processing (exactly one
    winner), writes idempotent events, advances the baseline on completed
    runs only. Returns a bounded summary dict. Never raises.
    """
    summary: dict = {"run_id": run_id, "change_status": "unknown", "events": 0}
    try:
        run = _load_run(db, run_id)
        if not run:
            summary["change_status"] = "skipped"
            return summary
        status = run["status"]
        if status == "failed":
            if (run.get("change_status") or "") == "pending":
                db.execute(
                    text("UPDATE monitoring_runs SET change_status = 'skipped' WHERE id = :rid"),
                    {"rid": run_id},
                )
                db.commit()
            summary["change_status"] = "skipped"
            return summary
        if status not in ("completed", "partial"):
            summary["change_status"] = "skipped"
            return summary
        claimed = db.execute(
            text(
                "UPDATE monitoring_runs SET change_status = 'processing', change_error = NULL "
                "WHERE id = :rid AND change_status = 'pending'"
            ),
            {"rid": run_id},
        )
        try:
            claimed_count = claimed.rowcount
        except Exception:
            claimed_count = 1
        if not claimed_count:
            try:
                current_status = (
                    db.execute(
                        text("SELECT change_status FROM monitoring_runs WHERE id = :rid"),
                        {"rid": run_id},
                    ).fetchone()
                )
                summary["change_status"] = (
                    current_status[0] if current_status else "unknown"
                )
            except Exception:
                summary["change_status"] = "unknown"
            try:
                db.rollback()
            except Exception:
                pass
            return summary
        try:
            return _process_claimed_run(db, run, summary)
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                pass
            err = str(exc)[:500]
            try:
                db.execute(
                    text(
                        "UPDATE monitoring_runs SET change_status = 'failed', "
                        "change_error = :err WHERE id = :rid"
                    ),
                    {"err": err, "rid": run_id},
                )
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            summary["change_status"] = "failed"
            summary["error"] = err
            return summary
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        summary["change_status"] = "failed"
        summary["error"] = str(exc)[:500]
        return summary


def _process_claimed_run(db, run, summary: dict) -> dict:
    run_id = run["id"]
    config_id = run["monitoring_config_id"]
    project_id = run["project_id"]
    complete = run["status"] == "completed"
    now = _utcnow_naive()
    scan_ids = _parse_json(run.get("scan_ids")) or []
    if not isinstance(scan_ids, list):
        scan_ids = []

    obs = _load_current_observation(db, project_id, scan_ids)
    has_content = bool(obs["assets"]) or bool(obs["findings"])
    base = _load_baseline(db, config_id)

    if base is None:
        if run["status"] == "completed" and has_content:
            _store_baseline(db, config_id, run_id, obs, now)
            db.execute(
                text(
                    "UPDATE monitoring_runs SET change_status = 'completed', "
                    "change_error = NULL, change_events_count = 0 WHERE id = :rid"
                ),
                {"rid": run_id},
            )
            db.commit()
            summary.update(
                {"change_status": "completed", "events": 0, "baseline": "established"}
            )
        else:
            db.execute(
                text(
                    "UPDATE monitoring_runs SET change_status = 'completed', "
                    "change_error = NULL, change_events_count = 0 WHERE id = :rid"
                ),
                {"rid": run_id},
            )
            db.commit()
            summary.update(
                {"change_status": "completed", "events": 0, "baseline": "deferred"}
            )
        return summary

    base_obs = {
        "assets": _parse_json(base.get("assets")) or {},
        "findings": _parse_json(base.get("findings")) or {},
        "relationships": _parse_json(base.get("relationships")) or {},
    }
    prev_run_id = base.get("run_id")
    if not has_content:
        db.execute(
            text(
                "UPDATE monitoring_runs SET change_status = 'completed', "
                "change_error = NULL, change_events_count = 0 WHERE id = :rid"
            ),
            {"rid": run_id},
        )
        db.commit()
        summary.update({"change_status": "completed", "events": 0, "baseline": "kept-empty"})
        return summary

    events = compare_observations(base_obs, obs, complete)
    completeness = "complete" if complete else "partial"
    created = 0
    for ev in events:
        key = _event_key(project_id, config_id, prev_run_id, run_id, ev)
        try:
            res = db.execute(
                text(
                    "INSERT INTO monitoring_change_events (id, project_id, "
                    "monitoring_config_id, prev_run_id, curr_run_id, change_type, "
                    "asset_id, finding_id, scan_id, previous_state, current_state, "
                    "scanners, scan_ids, completeness, event_key, detected_at, metadata) "
                    "VALUES (:id, :pid, :cid, :prev, :curr, :ctype, :aid, :fid, :sid, "
                    ":pstate, :cstate, :scanners, :scanids, :compl, :ekey, :now, :meta) "
                    "ON CONFLICT (event_key) DO NOTHING"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "pid": project_id,
                    "cid": config_id,
                    "prev": prev_run_id,
                    "curr": run_id,
                    "ctype": ev["change_type"],
                    "aid": ev.get("asset_id"),
                    "fid": ev.get("finding_id"),
                    "sid": ev.get("scan_id"),
                    "pstate": json.dumps(_summarize(ev.get("previous_state")))
                    if ev.get("previous_state") is not None
                    else None,
                    "cstate": json.dumps(_summarize(ev.get("current_state")))
                    if ev.get("current_state") is not None
                    else None,
                    "scanners": json.dumps(obs.get("scanners") or []),
                    "scanids": json.dumps(list(scan_ids)),
                    "compl": completeness,
                    "ekey": key,
                    "now": now,
                    "meta": json.dumps(
                        {
                            "monitoring_config_id": config_id,
                            "prev_run_id": prev_run_id,
                            "curr_run_id": run_id,
                            "scanner_versions": obs.get("versions") or {},
                        }
                    ),
                },
            )
            try:
                if res.rowcount:
                    created += int(res.rowcount)
            except Exception:
                created += 1
        except Exception:
            continue
    if complete:
        _store_baseline(db, config_id, run_id, obs, now)
        baseline_note = "advanced"
    else:
        baseline_note = "kept-partial"
    db.execute(
        text(
            "UPDATE monitoring_runs SET change_status = 'completed', change_error = NULL, "
            "change_events_count = :n WHERE id = :rid"
        ),
        {"n": created, "rid": run_id},
    )
    db.commit()
    summary.update(
        {"change_status": "completed", "events": created, "baseline": baseline_note}
    )
    return summary
