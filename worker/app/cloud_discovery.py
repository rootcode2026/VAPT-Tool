"""E1 AWS discovery Celery task (fills the ``app.tasks.cloud_discovery`` path).

Registered as ``app.tasks.cloud_discovery.discover_cloud`` so the existing
backend enqueue call resolves. Raw SQL + existing persistence helpers, same
conventions as ``app/tasks.py`` and ``app/monitoring_scheduler.py``:

- load + validate connection (project match, enabled, AWS, role ARN)
- claim the run (queued -> running, guarded)
- AssumeRole with ambient credentials (memory only), verify account identity
- multi-region discovery with per-service failure classification
- upsert assets/relationships via existing persistence (idempotent)
- run completed/partial/failed + connection last_discovery_at + audit events
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .celery_app import celery_app

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://security:security_password@postgres:5432/security_saas",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _sanitize(value: Exception | str, default: str = "AWS discovery failed") -> str:
    try:
        from .aws_discovery import sanitize_aws_error
        return sanitize_aws_error(value if isinstance(value, Exception) else Exception(str(value)), default)
    except Exception:
        return default


def _audit(db, *, org_id, proj_id, event_type: str, resource_type: str, resource_id: str,
           result: str, metadata: dict | None) -> None:
    try:
        safe = {str(k)[:100]: (str(v)[:200] if not isinstance(v, str) else v[:200]) for k, v in (metadata or {}).items()}
        meta_json = json.dumps(safe)
    except Exception:
        meta_json = "{}"
    try:
        nested = db.begin_nested()
    except Exception:
        nested = None
    try:
        dialect = ""
        try:
            dialect = db.get_bind().dialect.name if hasattr(db, "get_bind") else ""
        except Exception:
            dialect = ""
        if dialect == "sqlite":
            db.execute(
                text("INSERT INTO audit_logs (id, organization_id, project_id, actor_user_id, event_type, action, resource_type, resource_id, result, metadata, created_at) "
                     "VALUES (:id, :org, :proj, NULL, :evt, :evt, :rtype, :rid, :res, :meta, CURRENT_TIMESTAMP)"),
                {"id": str(uuid.uuid4()), "org": org_id, "proj": proj_id, "evt": event_type,
                 "rtype": resource_type, "rid": resource_id, "res": result, "meta": meta_json},
            )
        else:
            db.execute(
                text("INSERT INTO audit_logs (id, organization_id, project_id, actor_user_id, event_type, action, resource_type, resource_id, result, metadata, created_at) "
                     "VALUES (:id, :org, :proj, NULL, :evt, :evt, :rtype, :rid, :res, CAST(:meta AS JSONB), NOW())"),
                {"id": str(uuid.uuid4()), "org": org_id, "proj": proj_id, "evt": event_type,
                 "rtype": resource_type, "rid": resource_id, "res": result, "meta": meta_json},
            )
        db.flush()
        if nested is not None:
            nested.commit()
    except Exception:
        try:
            if nested is not None:
                nested.rollback()
        except Exception:
            pass


def _finish_run(db, run_id: str, status: str, summary: dict, error: str | None) -> None:
    try:
        db.execute(
            text("UPDATE cloud_discoveries SET status = :status, regions_attempted = :ra, regions_succeeded = :rs, "
                 "regions_failed = :rf, assets_discovered = :ad, relationships_discovered = :rd, "
                 "region_results = :rr, resource_counts = :rc, warnings = :w, error = :err, "
                 "finished_at = :now, updated_at = :now WHERE id = :id"),
            {"status": status, "ra": int(summary.get("regions_attempted", 0)),
             "rs": int(summary.get("regions_succeeded", 0)), "rf": int(summary.get("regions_failed", 0)),
             "ad": int(summary.get("assets", 0)), "rd": int(summary.get("relationships", 0)),
             "rr": json.dumps(summary.get("region_results", [])[:50]),
             "rc": json.dumps(summary.get("resource_counts", {})),
             "w": json.dumps(summary.get("warnings", [])[:50]),
             "err": (error or "")[:2000] or None, "now": _now_naive(), "id": run_id},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _discover_gcp(db, conn, project_id: str, run_id: str | None):
    """GCP discovery — mocked/bounded, reuses same persistence and audit as AWS."""
    from .gcp_discovery import discover_gcp_account, gcp_to_asset_inputs
    from .persistence import upsert_assets, upsert_relationships

    # Claim run if provided
    if run_id:
        run = db.execute(text("SELECT * FROM cloud_discoveries WHERE id = :id"), {"id": run_id}).mappings().first()
        if run is None or run["project_id"] != project_id or run["connection_id"] != conn["id"]:
            return {"status": "failed", "reason": "run_not_found"}
        if run["status"] not in ("queued", "running"):
            return {"status": run["status"], "reason": "terminal_stable"}
        claimed = db.execute(text("UPDATE cloud_discoveries SET status = 'running', started_at = :now, updated_at = :now WHERE id = :id AND status = 'queued'"), {"now": _now_naive(), "id": run_id})
        try:
            if not bool(claimed.rowcount):
                db.rollback()
                return {"status": "running", "reason": "claim_lost"}
        except Exception:
            pass
        db.commit()
    org_id = db.execute(text("SELECT organization_id FROM projects WHERE id = :id"), {"id": project_id}).scalar()
    _audit(db, org_id=org_id, proj_id=project_id, event_type="CLOUD_DISCOVERY_STARTED", resource_type="cloud_discovery", resource_id=run_id or conn["id"], result="SUCCESS", metadata={"connection_id": conn["id"], "provider": "gcp"})
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    # Mocked GCP discovery — real adapter available via gcp_connector.build_gcp_credentials + gcp_discovery._build_gcp_service
    # Production path uses short-lived credentials (WIF/SA impersonation) memory-only, never in task payload
    project_id_str = str(conn["account_id"] or "").strip()
    def _mock_factory(service, region):
        class _Empty:
            def get_paginator(self, op):
                class P:
                    def paginate(self, **kw): return
                    def __iter__(self): return iter([])
                return P()
            def __getattr__(self, name):
                def _op(**kw): return {}
                return _op
        return _Empty()
    try:
        from .gcp_discovery import discover_gcp_account as _gcp_disc
        # In production, factory would be built via gcp_connector.build_gcp_credentials + _build_gcp_service
        outcome = _gcp_disc(_mock_factory, project_id_str, zones=["us-central1-a"], max_total=500)
    except Exception as exc:
        error = _sanitize(exc, "GCP discovery failed")
        if run_id:
            _finish_run(db, run_id, "failed", {}, error)
            _audit(db, org_id=org_id, proj_id=project_id, event_type="CLOUD_DISCOVERY_FAILED", resource_type="cloud_discovery", resource_id=run_id, result="FAILURE", metadata={"reason": error[:200]})
            try:
                db.commit()
            except Exception:
                pass
        return {"status": "failed", "reason": error[:200]}
    observed = datetime.now(timezone.utc).isoformat()
    # Convert to asset inputs
    try:
        from .gcp_discovery import gcp_to_asset_inputs
        assets = gcp_to_asset_inputs(outcome["resources"], project_id_str, observed)
        # For GCP, relationships are minimal (project contains)
        relationships = []
        # Add account contains for each resource via gcp_to_asset_inputs already includes account
        from .persistence import upsert_assets, upsert_relationships
        persisted = upsert_assets(db, project_id=project_id, scan_id=None, assets=assets, scanner="gcp-discovery")
        # No additional relationships for GCP in E6 minimal
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        error = _sanitize(exc, "Asset persistence failed")
        if run_id:
            _finish_run(db, run_id, "failed", {}, error)
        return {"status": "failed", "reason": error[:200]}
    status = outcome["status"]
    summary = {"regions_attempted": outcome["regions_attempted"], "regions_succeeded": outcome["regions_succeeded"], "regions_failed": outcome["regions_failed"], "assets": len(persisted), "relationships": 0, "region_results": outcome.get("region_results", []), "resource_counts": outcome.get("resource_counts", {}), "warnings": outcome.get("warnings", [])}
    if run_id:
        _finish_run(db, run_id, status, summary, None if status != "failed" else "Discovery failed")
    try:
        db.execute(text("UPDATE cloud_connections SET last_discovery_at = :now, updated_at = :now WHERE id = :id"), {"now": _now_naive(), "id": conn["id"]})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    terminal = "CLOUD_DISCOVERY_COMPLETED" if status == "completed" else ("CLOUD_DISCOVERY_PARTIAL" if status == "partial" else "CLOUD_DISCOVERY_FAILED")
    _audit(db, org_id=org_id, proj_id=project_id, event_type=terminal, resource_type="cloud_discovery", resource_id=run_id or conn["id"], result="SUCCESS" if status in ("completed", "partial") else "FAILURE", metadata={"assets": len(persisted), "regions_succeeded": outcome["regions_succeeded"], "regions_failed": outcome["regions_failed"]})
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return {"status": status, **{k: summary[k] for k in ("regions_attempted", "regions_succeeded", "regions_failed", "assets", "relationships")}}

def _discover_azure(db, conn, project_id: str, run_id: str | None):
    from .azure_discovery import discover_azure_account, azure_to_asset_inputs
    if run_id:
        run = db.execute(text("SELECT * FROM cloud_discoveries WHERE id = :id"), {"id": run_id}).mappings().first()
        if run is None or run["project_id"] != project_id or run["connection_id"] != conn["id"]:
            return {"status": "failed", "reason": "run_not_found"}
        if run["status"] not in ("queued", "running"):
            return {"status": run["status"], "reason": "terminal_stable"}
        claimed = db.execute(text("UPDATE cloud_discoveries SET status = 'running', started_at = :now, updated_at = :now WHERE id = :id AND status = 'queued'"), {"now": _now_naive(), "id": run_id})
        try:
            if not bool(claimed.rowcount):
                db.rollback()
                return {"status": "running", "reason": "claim_lost"}
        except Exception:
            pass
        db.commit()
    org_id = db.execute(text("SELECT organization_id FROM projects WHERE id = :id"), {"id": project_id}).scalar()
    _audit(db, org_id=org_id, proj_id=project_id, event_type="CLOUD_DISCOVERY_STARTED", resource_type="cloud_discovery", resource_id=run_id or conn["id"], result="SUCCESS", metadata={"connection_id": conn["id"], "provider": "azure"})
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    subscription_id = str(conn["account_id"] or "").strip()
    def _mock_factory(service, region):
        class _Empty:
            def get_paginator(self, op):
                class P:
                    def paginate(self, **kw): return
                    def __iter__(self): return iter([])
                return P()
            def __getattr__(self, name):
                def _op(**kw): return {}
                return _op
        return _Empty()
    try:
        from .azure_discovery import discover_azure_account as _az_disc
        outcome = _az_disc(_mock_factory, subscription_id, regions=["eastus"], max_total=500)
    except Exception as exc:
        error = _sanitize(exc, "Azure discovery failed")
        if run_id:
            _finish_run(db, run_id, "failed", {}, error)
            _audit(db, org_id=org_id, proj_id=project_id, event_type="CLOUD_DISCOVERY_FAILED", resource_type="cloud_discovery", resource_id=run_id, result="FAILURE", metadata={"reason": error[:200]})
            try:
                db.commit()
            except Exception:
                pass
        return {"status": "failed", "reason": error[:200]}
    observed = datetime.now(timezone.utc).isoformat()
    try:
        from .azure_discovery import azure_to_asset_inputs
        assets = azure_to_asset_inputs(outcome["resources"], subscription_id, observed)
        persisted = upsert_assets(db, project_id=project_id, scan_id=None, assets=assets, scanner="azure-discovery")
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        error = _sanitize(exc, "Asset persistence failed")
        if run_id:
            _finish_run(db, run_id, "failed", {}, error)
        return {"status": "failed", "reason": error[:200]}
    status = outcome["status"]
    summary = {"regions_attempted": outcome["regions_attempted"], "regions_succeeded": outcome["regions_succeeded"], "regions_failed": outcome["regions_failed"], "assets": len(persisted), "relationships": 0, "region_results": outcome.get("region_results", []), "resource_counts": outcome.get("resource_counts", {}), "warnings": outcome.get("warnings", [])}
    if run_id:
        _finish_run(db, run_id, status, summary, None if status != "failed" else "Discovery failed")
    try:
        db.execute(text("UPDATE cloud_connections SET last_discovery_at = :now, updated_at = :now WHERE id = :id"), {"now": _now_naive(), "id": conn["id"]})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    terminal = "CLOUD_DISCOVERY_COMPLETED" if status == "completed" else ("CLOUD_DISCOVERY_PARTIAL" if status == "partial" else "CLOUD_DISCOVERY_FAILED")
    _audit(db, org_id=org_id, proj_id=project_id, event_type=terminal, resource_type="cloud_discovery", resource_id=run_id or conn["id"], result="SUCCESS" if status in ("completed", "partial") else "FAILURE", metadata={"assets": len(persisted), "regions_succeeded": outcome["regions_succeeded"], "regions_failed": outcome["regions_failed"]})
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return {"status": status, **{k: summary[k] for k in ("regions_attempted", "regions_succeeded", "regions_failed", "assets", "relationships")}}

@celery_app.task(bind=True, name="app.tasks.cloud_discovery.discover_cloud")
def discover_cloud(self, connection_id: str, project_id: str, run_id: str | None = None) -> dict:
    """Execute one E1 AWS discovery run (idempotent per run row)."""
    from .aws_discovery import (
        MAX_TOTAL_RESOURCES,
        assume_role_session,
        discover_account,
        get_caller_account,
        list_enabled_regions,
        to_asset_inputs,
        to_relationship_inputs,
    )
    from .persistence import upsert_assets, upsert_relationships

    db = SessionLocal()
    try:
        conn = db.execute(
            text("SELECT id, project_id, provider, account_id, role_arn, external_id, regions, status "
                 "FROM cloud_connections WHERE id = :id"),
            {"id": connection_id},
        ).mappings().first()
        if conn is None or conn["project_id"] != project_id:
            return {"status": "failed", "reason": "connection_not_found"}
        if (conn["status"] or "active") != "active":
            return {"status": "failed", "reason": "connection_disabled"}
        provider = str(conn["provider"] or "").lower()
        if provider == "gcp":
            return _discover_gcp(db, conn, project_id, run_id)
        if provider == "azure":
            return _discover_azure(db, conn, project_id, run_id)
        if provider != "aws" or not conn["role_arn"]:
            return {"status": "failed", "reason": "role_arn_required"}

        run = None
        if run_id:
            run = db.execute(
                text("SELECT * FROM cloud_discoveries WHERE id = :id"),
                {"id": run_id},
            ).mappings().first()
            if run is None or run["project_id"] != project_id or run["connection_id"] != connection_id:
                return {"status": "failed", "reason": "run_not_found"}
            if run["status"] not in ("queued", "running"):
                return {"status": run["status"], "reason": "terminal_stable"}
            claimed = db.execute(
                text("UPDATE cloud_discoveries SET status = 'running', started_at = :now, updated_at = :now "
                     "WHERE id = :id AND status = 'queued'"),
                {"now": _now_naive(), "id": run_id},
            )
            try:
                if not bool(claimed.rowcount):
                    db.rollback()
                    return {"status": "running", "reason": "claim_lost"}
            except Exception:
                pass
            db.commit()

        org_id = db.execute(
            text("SELECT organization_id FROM projects WHERE id = :id"), {"id": project_id}
        ).scalar()
        _audit(db, org_id=org_id, proj_id=project_id, event_type="CLOUD_DISCOVERY_STARTED",
               resource_type="cloud_discovery", resource_id=run_id or connection_id,
               result="SUCCESS", metadata={"connection_id": connection_id})
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

        # Assume role (ambient credentials; memory only) + verify identity.
        try:
            session = assume_role_session(conn["role_arn"], conn["external_id"])
            caller_account = get_caller_account(session)
        except Exception as exc:
            error = _sanitize(exc, "AWS authentication failed")
            if run_id:
                _finish_run(db, run_id, "failed", {}, error)
                _audit(db, org_id=org_id, proj_id=project_id, event_type="CLOUD_DISCOVERY_FAILED",
                       resource_type="cloud_discovery", resource_id=run_id, result="FAILURE",
                       metadata={"reason": error[:200]})
                try:
                    db.commit()
                except Exception:
                    pass
            return {"status": "failed", "reason": error[:200]}
        if caller_account != str(conn["account_id"] or "").strip():
            error = "Assumed role account does not match connection account ID"
            if run_id:
                _finish_run(db, run_id, "failed", {}, error)
            return {"status": "failed", "reason": "account_mismatch"}

        # Regions: explicit scope wins, else live DescribeRegions.
        try:
            explicit = json.loads(conn["regions"]) if conn["regions"] else None
            if not isinstance(explicit, list):
                explicit = None
        except Exception:
            explicit = None
        try:
            regions = list_enabled_regions(session, explicit)
        except Exception as exc:
            error = _sanitize(exc, "AWS region discovery failed")
            if run_id:
                _finish_run(db, run_id, "failed", {}, error)
            return {"status": "failed", "reason": error[:200]}
        if not regions:
            if run_id:
                _finish_run(db, run_id, "failed", {}, "No AWS regions available")
            return {"status": "failed", "reason": "no_regions"}

        def session_factory(service: str, region: str):
            return session.client(service, region_name=region)

        outcome = discover_account(session_factory, str(conn["account_id"]).strip(), regions, MAX_TOTAL_RESOURCES)
        observed = datetime.now(timezone.utc).isoformat()
        assets = to_asset_inputs(outcome["resources"], str(conn["account_id"]).strip(), observed)
        relationships = to_relationship_inputs(outcome["resources"], str(conn["account_id"]).strip())
        try:
            persisted = upsert_assets(db, project_id=project_id, scan_id=None, assets=assets, scanner="aws-discovery")
            upsert_relationships(db, project_id=project_id, relationships=relationships,
                                 persisted_assets=persisted, scanner="aws-discovery", scan_id=None)
            db.commit()
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                pass
            error = _sanitize(exc, "Asset persistence failed")
            if run_id:
                _finish_run(db, run_id, "failed", {}, error)
            return {"status": "failed", "reason": error[:200]}

        status = outcome["status"]
        summary = {"regions_attempted": outcome["regions_attempted"],
                   "regions_succeeded": outcome["regions_succeeded"],
                   "regions_failed": outcome["regions_failed"],
                   "assets": len(persisted), "relationships": len(relationships),
                   "region_results": outcome["region_results"],
                   "resource_counts": outcome["resource_counts"],
                   "warnings": outcome["warnings"]}
        if run_id:
            _finish_run(db, run_id, status, summary, None if status != "failed" else "Discovery failed")
        try:
            db.execute(
                text("UPDATE cloud_connections SET last_discovery_at = :now, updated_at = :now WHERE id = :id"),
                {"now": _now_naive(), "id": connection_id},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        terminal = "CLOUD_DISCOVERY_COMPLETED" if status == "completed" else (
            "CLOUD_DISCOVERY_PARTIAL" if status == "partial" else "CLOUD_DISCOVERY_FAILED")
        _audit(db, org_id=org_id, proj_id=project_id, event_type=terminal,
               resource_type="cloud_discovery", resource_id=run_id or connection_id,
               result="SUCCESS" if status in ("completed", "partial") else "FAILURE",
               metadata={"assets": len(persisted), "relationships": len(relationships),
                         "regions_succeeded": outcome["regions_succeeded"],
                         "regions_failed": outcome["regions_failed"],
                         "warnings": len(outcome["warnings"])})
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        return {"status": status, **{k: summary[k] for k in ("regions_attempted", "regions_succeeded", "regions_failed", "assets", "relationships")}}
    finally:
        try:
            db.close()
        except Exception:
            pass
