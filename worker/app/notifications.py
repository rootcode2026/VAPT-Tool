"""D9 notification delivery worker (local/test provider sink).

The backend package is intentionally NOT imported here: the worker image only
ships ``worker/app``. This module uses plain SQL against the same PostgreSQL
schema the backend owns, mirroring ``app/tasks.py`` and
``app/monitoring_scheduler.py`` conventions.

Task ``app.notifications.deliver_notification(delivery_id)``:

1. Load the delivery; CAS-claim ``pending -> sending`` (rowcount guard: a lost
   race returns safely, never double-sends).
2. Re-validate tenant context (delivery/alert/policy project match).
3. Read the policy ``provider_config.fail_mode`` test hook (allowlisted enum).
4. ``none`` -> insert bounded outbox row + mark SENT (outbox PK makes a
   redelivered accept idempotent).
5. ``temporary`` -> raise for bounded Celery retry (attempt-capped).
6. ``permanent``/misconfig -> FAILED with sanitized classification (no retry).
7. Audit SENT/FAILED via savepoint-isolated raw SQL (idempotency-guarded).

The ``local`` channel never performs network I/O. Email/webhooks are deferred.
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

MAX_DELIVERY_ATTEMPTS = 5
FAIL_MODES = ("none", "temporary", "permanent")


class TransientDeliveryError(Exception):
    """Retryable local-provider failure (raised for bounded Celery retry)."""


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_sqlite(db) -> bool:
    try:
        return (db.get_bind().dialect.name if hasattr(db, "get_bind") else "") == "sqlite"
    except Exception:
        return False


def _audit_exists(db, resource_id: str, event_type: str) -> bool:
    try:
        row = db.execute(
            text("SELECT 1 FROM audit_logs WHERE resource_id = :rid AND event_type = :evt LIMIT 1"),
            {"rid": resource_id, "evt": event_type},
        ).fetchone()
        return row is not None
    except Exception:
        return False


def _audit(db, *, org_id, proj_id, event_type: str, resource_id: str, metadata: dict | None) -> None:
    """Savepoint-isolated audit insert (never breaks delivery persistence)."""
    try:
        safe = {k: str(v)[:200] for k, v in (metadata or {}).items()}
        meta_json = json.dumps(safe) if safe else None
    except Exception:
        meta_json = None
    try:
        nested = db.begin_nested()
    except Exception:
        nested = None
    try:
        if _is_sqlite(db):
            db.execute(
                text(
                    "INSERT INTO audit_logs (id, organization_id, project_id, actor_user_id, "
                    "event_type, action, resource_type, resource_id, result, metadata, created_at) "
                    "VALUES (:id, :org, :proj, NULL, :evt, :evt, :rtype, :rid, 'SUCCESS', :meta, CURRENT_TIMESTAMP)"
                ),
                {"id": str(uuid.uuid4()), "org": org_id, "proj": proj_id, "evt": event_type,
                 "rtype": "notification_delivery", "rid": resource_id, "meta": meta_json},
            )
        else:
            db.execute(
                text(
                    "INSERT INTO audit_logs (id, organization_id, project_id, actor_user_id, "
                    "event_type, action, resource_type, resource_id, result, metadata, created_at) "
                    "VALUES (:id, :org, :proj, NULL, :evt, :evt, :rtype, :rid, 'SUCCESS', "
                    "CAST(:meta AS JSONB), NOW())"
                ),
                {"id": str(uuid.uuid4()), "org": org_id, "proj": proj_id, "evt": event_type,
                 "rtype": "notification_delivery", "rid": resource_id, "meta": meta_json},
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


def _mark_failed(db, delivery_id: str, classification: str, org_id, proj_id, alert_id, channel) -> dict:
    try:
        db.execute(
            text(
                "UPDATE notification_deliveries SET status = 'failed', "
                "last_error = :err, updated_at = :now WHERE id = :id"
            ),
            {"err": classification[:500], "now": _utcnow_naive(), "id": delivery_id},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    if not _audit_exists(db, delivery_id, "NOTIFICATION_FAILED"):
        _audit(db, org_id=org_id, proj_id=proj_id, event_type="NOTIFICATION_FAILED",
               resource_id=delivery_id, metadata={"alert_id": alert_id, "channel": channel, "reason": classification})
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    return {"delivery_id": delivery_id, "status": "failed", "reason": classification}


RETRYABLE_ATTEMPTS = 3


@celery_app.task(bind=True, name="app.notifications.deliver_notification")
def deliver_notification(self, delivery_id: str) -> dict:
    """Execute one local-channel delivery (idempotent, attempt-capped)."""
    db = SessionLocal()
    try:
        row = db.execute(
            text("SELECT * FROM notification_deliveries WHERE id = :id"),
            {"id": delivery_id},
        ).mappings().first()
        if row is None:
            return {"delivery_id": delivery_id, "status": "unknown", "reason": "not_found"}
        if row["status"] in ("sent", "failed", "cancelled"):
            return {"delivery_id": delivery_id, "status": row["status"], "reason": "terminal_stable"}
        if row["channel"] != "local":
            return _mark_failed(db, delivery_id, "permanent_provider_failure: unsupported channel", row["organization_id"], row["project_id"], row["alert_id"], row["channel"])
        if int(row["attempt_count"] or 0) >= MAX_DELIVERY_ATTEMPTS:
            return _mark_failed(db, delivery_id, "permanent_provider_failure: attempts exhausted", row["organization_id"], row["project_id"], row["alert_id"], row["channel"])

        # Atomic claim: only the winner proceeds (concurrent workers safe).
        claimed = db.execute(
            text(
                "UPDATE notification_deliveries SET status = 'sending', "
                "attempt_count = attempt_count + 1, updated_at = :now "
                "WHERE id = :id AND status = 'pending'"
            ),
            {"now": _utcnow_naive(), "id": delivery_id},
        )
        try:
            won = bool(claimed.rowcount)
        except Exception:
            won = True
        if not won:
            db.rollback()
            current = db.execute(
                text("SELECT status FROM notification_deliveries WHERE id = :id"),
                {"id": delivery_id},
            ).mappings().first()
            return {"delivery_id": delivery_id, "status": (current or {}).get("status", "unknown"), "reason": "claim_lost"}

        # Tenant re-validation: delivery, alert, and policy must agree.
        alert = db.execute(
            text("SELECT id, project_id, organization_id FROM alerts WHERE id = :id"),
            {"id": row["alert_id"]},
        ).mappings().first() if row["alert_id"] else None
        if alert is None or alert["project_id"] != row["project_id"] or alert["organization_id"] != row["organization_id"]:
            db.commit()
            return _mark_failed(db, delivery_id, "tenant_validation_failure", row["organization_id"], row["project_id"], row["alert_id"], row["channel"])

        fail_mode = "none"
        try:
            pol = db.execute(
                text("SELECT provider_config FROM notification_policies WHERE project_id = :pid"),
                {"pid": row["project_id"]},
            ).mappings().first()
            cfg = (pol or {}).get("provider_config")
            if isinstance(cfg, str):
                cfg = json.loads(cfg)
            if isinstance(cfg, dict) and str(cfg.get("fail_mode", "none")) in FAIL_MODES:
                fail_mode = str(cfg.get("fail_mode", "none"))
        except Exception:
            fail_mode = "none"

        if fail_mode == "temporary":
            # Release the claim so the retry re-claims cleanly; a concurrent
            # worker racing here loses its CAS and returns claim_lost.
            attempt_now = int((db.execute(
                text("SELECT attempt_count FROM notification_deliveries WHERE id = :id"),
                {"id": delivery_id},
            ).mappings().first() or {}).get("attempt_count") or 0)
            db.execute(
                text("UPDATE notification_deliveries SET status = 'pending', last_error = :err, updated_at = :now WHERE id = :id"),
                {"err": "temporary_provider_failure: retrying", "now": _utcnow_naive(), "id": delivery_id},
            )
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            if attempt_now >= RETRYABLE_ATTEMPTS:
                return _mark_failed(db, delivery_id, "temporary_provider_failure: retries exhausted", row["organization_id"], row["project_id"], row["alert_id"], row["channel"])
            raise self.retry(countdown=30, max_retries=RETRYABLE_ATTEMPTS, exc=TransientDeliveryError("temporary_provider_failure"))

        if fail_mode == "permanent":
            db.commit()
            return _mark_failed(db, delivery_id, "permanent_provider_failure", row["organization_id"], row["project_id"], row["alert_id"], row["channel"])

        # Accept into the bounded local outbox sink (PK => redelivery is a no-op).
        try:
            db.execute(
                text(
                    "INSERT INTO notification_outbox (delivery_id, channel, recipient_user_id, subject, body, created_at) "
                    "VALUES (:did, :ch, :uid, :subj, :body, :now)"
                ),
                {"did": delivery_id, "ch": "local", "uid": row["recipient_user_id"],
                 "subj": (row["subject"] or "Security alert")[:255],
                 "body": (row["body"] or "")[:2000], "now": _utcnow_naive()},
            )
        except Exception as exc:
            if "unique" not in str(exc).lower() and "duplicate" not in str(exc).lower() and "primary" not in str(exc).lower():
                try:
                    db.rollback()
                except Exception:
                    pass
                return _mark_failed(db, delivery_id, "permanent_provider_failure: outbox write failed", row["organization_id"], row["project_id"], row["alert_id"], row["channel"])
            try:
                db.rollback()
            except Exception:
                pass
        db.execute(
            text(
                "UPDATE notification_deliveries SET status = 'sent', "
                "provider_message_id = :pmid, sent_at = :now, last_error = NULL, updated_at = :now "
                "WHERE id = :id"
            ),
            {"pmid": f"local-{delivery_id[:8]}", "now": _utcnow_naive(), "id": delivery_id},
        )
        db.commit()
        if not _audit_exists(db, delivery_id, "NOTIFICATION_SENT"):
            _audit(db, org_id=row["organization_id"], proj_id=row["project_id"], event_type="NOTIFICATION_SENT",
                   resource_id=delivery_id, metadata={"alert_id": row["alert_id"], "channel": "local"})
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
        return {"delivery_id": delivery_id, "status": "sent"}
    finally:
        try:
            db.close()
        except Exception:
            pass
