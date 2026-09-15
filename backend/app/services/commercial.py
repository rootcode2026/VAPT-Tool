"""Commercial — plan catalog, entitlements, limits, subscriptions, license, usage — deterministic, tenant-scoped."""
from __future__ import annotations
import uuid, hmac, hashlib, json
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from app.models.commercial import Plan, Subscription, License, UsageEvent

# Plans — DB-backed, Decimal safe
def list_plans(db: Session, active_only: bool = True) -> list[Plan]:
    q=db.query(Plan)
    if active_only:
        q=q.filter(Plan.active==True)
    return q.order_by(Plan.monthly_price.asc().nulls_last()).all()

def get_plan(db: Session, plan_id: str) -> Plan | None:
    return db.query(Plan).filter(Plan.id==plan_id).first()

def get_plan_by_code(db: Session, code: str) -> Plan | None:
    return db.query(Plan).filter(Plan.code==code.lower()).first()

# Entitlements — server-side evaluation
def check_entitlement(db: Session, organization_id: str, key: str) -> bool:
    # resolve via license entitlement_snapshot, fallback to plan entitlements
    lic=db.query(License).filter(License.organization_id==organization_id, License.status.in_(["active","grace"])).order_by(License.created_at.desc()).first()
    if lic and lic.entitlement_snapshot:
        return bool(lic.entitlement_snapshot.get(key, False))
    # fallback to subscription plan
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id, Subscription.status.in_(["trialing","active","past_due","grace_period"])).order_by(Subscription.created_at.desc()).first()
    if sub:
        plan=get_plan(db, sub.plan_id)
        if plan and plan.entitlements:
            return bool(plan.entitlements.get(key, False))
    # default free plan
    free=get_plan_by_code(db, "free")
    if free and free.entitlements:
        return bool(free.entitlements.get(key, False))
    return False

def get_entitlements(db: Session, organization_id: str) -> dict:
    lic=db.query(License).filter(License.organization_id==organization_id, License.status.in_(["active","grace"])).order_by(License.created_at.desc()).first()
    if lic:
        return lic.entitlement_snapshot or {}
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id, Subscription.status.in_(["trialing","active","past_due","grace_period"])).order_by(Subscription.created_at.desc()).first()
    if sub:
        plan=get_plan(db, sub.plan_id)
        if plan:
            return plan.entitlements or {}
    free=get_plan_by_code(db, "free")
    return free.entitlements if free else {}

def get_limits(db: Session, organization_id: str) -> dict:
    lic=db.query(License).filter(License.organization_id==organization_id, License.status.in_(["active","grace"])).order_by(License.created_at.desc()).first()
    if lic and lic.limits_snapshot:
        return lic.limits_snapshot
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id, Subscription.status.in_(["trialing","active","past_due","grace_period"])).order_by(Subscription.created_at.desc()).first()
    if sub:
        plan=get_plan(db, sub.plan_id)
        if plan and plan.limits:
            return plan.limits
        # also direct columns
        if plan:
            return {"assets": plan.asset_limit, "users": plan.user_limit, "projects": plan.project_limit, "scans": plan.scan_limit}
    free=get_plan_by_code(db, "free")
    if free:
        return free.limits or {"assets": free.asset_limit, "users": free.user_limit, "projects": free.project_limit}
    return {}

def check_limit(db: Session, organization_id: str, limit_key: str, requested: int = 1) -> tuple[bool, str]:
    limits=get_limits(db, organization_id)
    max_val=limits.get(limit_key)
    if max_val is None:
        return True, ""
    # get usage
    usage=get_usage(db, organization_id, limit_key)
    if usage + requested > int(max_val):
        return False, f"Limit exceeded for {limit_key}: {usage}/{max_val}"
    return True, ""

def get_usage(db: Session, organization_id: str, event_type: str) -> int:
    # sum quantity for usage_events of type, plus live counts for assets/users/projects where relevant
    if event_type=="assets":
        from app.models.asset import Asset
        # count assets via organization's projects
        from app.models.project import Project
        proj_ids=[r[0] for r in db.query(Project.id).filter(Project.organization_id==organization_id).all()]
        if not proj_ids:
            return 0
        return db.query(func.count(Asset.id)).filter(Asset.project_id.in_(proj_ids)).scalar() or 0
    if event_type=="projects":
        from app.models.project import Project
        return db.query(func.count(Project.id)).filter(Project.organization_id==organization_id).scalar() or 0
    if event_type=="users":
        from app.models.user import User
        return db.query(func.count(User.id)).filter(User.organization_id==organization_id).scalar() or 0
    # for scans, use usage_events
    total=db.query(func.coalesce(func.sum(UsageEvent.quantity),0)).filter(UsageEvent.organization_id==organization_id, UsageEvent.event_type==event_type).scalar() or 0
    return int(total)

# Subscriptions
def create_subscription(db: Session, organization_id: str, plan_code: str, billing_interval: str = "monthly", provider: str = "mock") -> Subscription:
    plan=get_plan_by_code(db, plan_code)
    if not plan:
        raise ValueError(f"Plan not found: {plan_code}")
    if billing_interval not in ("monthly","annual","trial"):
        raise ValueError("Invalid billing interval")
    now=datetime.now(timezone.utc)
    renewal = now + timedelta(days=30 if billing_interval=="monthly" else 365 if billing_interval=="annual" else 14)
    sub=Subscription(id=str(uuid.uuid4()), organization_id=organization_id, plan_id=plan.id, status="active" if billing_interval!="trial" else "trialing", billing_interval=billing_interval, start_date=now, renewal_date=renewal, provider=provider)
    db.add(sub); db.flush()
    # issue license
    lic=License(id=str(uuid.uuid4()), organization_id=organization_id, plan_id=plan.id, subscription_id=sub.id, status="active", edition=plan.code, entitlement_snapshot=plan.entitlements or {}, limits_snapshot=plan.limits or {"assets": plan.asset_limit, "users": plan.user_limit, "projects": plan.project_limit}, issued_at=now, expires_at=renewal, issuer_version="v1")
    db.add(lic); db.commit(); db.refresh(sub)
    return sub

def change_subscription(db: Session, organization_id: str, new_plan_code: str) -> Subscription:
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id, Subscription.status.in_(["trialing","active","past_due","grace_period"])).order_by(Subscription.created_at.desc()).first()
    if not sub:
        raise ValueError("No active subscription")
    plan=get_plan_by_code(db, new_plan_code)
    if not plan:
        raise ValueError(f"Plan not found: {new_plan_code}")
    old_plan=get_plan(db, sub.plan_id)
    # allow upgrade/downgrade deterministically; downgrade to free allowed
    sub.plan_id=plan.id
    sub.updated_at=datetime.now(timezone.utc)
    # update license
    lic=db.query(License).filter(License.organization_id==organization_id, License.subscription_id==sub.id).order_by(License.created_at.desc()).first()
    if lic:
        lic.plan_id=plan.id
        lic.entitlement_snapshot=plan.entitlements or {}
        lic.limits_snapshot=plan.limits or {"assets": plan.asset_limit}
        lic.edition=plan.code
    db.commit(); db.refresh(sub)
    return sub

def cancel_subscription(db: Session, organization_id: str) -> Subscription:
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id, Subscription.status.in_(["trialing","active","past_due","grace_period"])).order_by(Subscription.created_at.desc()).first()
    if not sub:
        raise ValueError("No active subscription")
    sub.status="cancelled"
    sub.cancellation_date=datetime.now(timezone.utc)
    # grace period 7 days then expired
    lic=db.query(License).filter(License.organization_id==organization_id, License.subscription_id==sub.id).order_by(License.created_at.desc()).first()
    if lic:
        lic.status="grace"
        lic.expires_at=datetime.now(timezone.utc)+timedelta(days=7)
    db.commit(); db.refresh(sub)
    return sub

# License validation — server-side, deterministic, no client trust
def validate_license(db: Session, organization_id: str) -> dict:
    lic=db.query(License).filter(License.organization_id==organization_id).order_by(License.created_at.desc()).first()
    if not lic:
        return {"valid": False, "status": "missing", "entitlements": {}, "limits": {}}
    now=datetime.now(timezone.utc)
    exp=lic.expires_at
    if exp and exp.tzinfo is None:
        exp=exp.replace(tzinfo=timezone.utc)
    if lic.status=="revoked":
        return {"valid": False, "status": "revoked", "entitlements": lic.entitlement_snapshot, "limits": lic.limits_snapshot}
    if exp and now > exp:
        return {"valid": False, "status": "expired", "entitlements": lic.entitlement_snapshot, "limits": lic.limits_snapshot}
    if lic.status in ("active","grace"):
        return {"valid": True, "status": lic.status, "entitlements": lic.entitlement_snapshot, "limits": lic.limits_snapshot, "expires_at": exp.isoformat() if exp else None}
    return {"valid": False, "status": lic.status, "entitlements": lic.entitlement_snapshot, "limits": lic.limits_snapshot}

# Usage metering — idempotent via event_key
def record_usage(db: Session, organization_id: str, event_type: str, event_key: str, quantity: int = 1, metadata: dict | None = None) -> UsageEvent:
    existing=db.query(UsageEvent).filter(UsageEvent.organization_id==organization_id, UsageEvent.event_key==event_key).first()
    if existing:
        return existing
    ev=UsageEvent(id=str(uuid.uuid4()), organization_id=organization_id, event_type=event_type, event_key=event_key, quantity=quantity, metadata_=metadata or {})
    db.add(ev); db.commit(); db.refresh(ev)
    return ev

def usage_summary(db: Session, organization_id: str) -> dict:
    rows=db.query(UsageEvent.event_type, func.sum(UsageEvent.quantity)).filter(UsageEvent.organization_id==organization_id).group_by(UsageEvent.event_type).all()
    summary={r[0]: int(r[1]) for r in rows}
    # add live counts
    summary["assets_live"]=get_usage(db, organization_id, "assets")
    summary["projects_live"]=get_usage(db, organization_id, "projects")
    summary["users_live"]=get_usage(db, organization_id, "users")
    return summary

# Payment provider abstraction — provider-neutral, mock deterministic
class PaymentProvider:
    def create_customer(self, organization_id: str, email: str) -> dict: raise NotImplementedError
    def create_checkout(self, organization_id: str, plan_code: str, interval: str) -> dict: raise NotImplementedError
    def create_subscription(self, organization_id: str, plan_code: str) -> dict: raise NotImplementedError
    def cancel_subscription(self, provider_subscription_id: str) -> dict: raise NotImplementedError
    def verify_webhook(self, payload: bytes, signature: str, secret: str) -> bool: raise NotImplementedError

class MockPaymentProvider(PaymentProvider):
    def create_customer(self, organization_id, email):
        return {"provider_customer_id": f"cus_mock_{organization_id[:8]}", "email": email}
    def create_checkout(self, organization_id, plan_code, interval):
        return {"checkout_url": f"https://mock.pay/checkout/{organization_id}/{plan_code}/{interval}", "session_id": f"cs_{uuid.uuid4().hex[:8]}"}
    def create_subscription(self, organization_id, plan_code):
        return {"provider_subscription_id": f"sub_mock_{uuid.uuid4().hex[:8]}", "status": "active"}
    def cancel_subscription(self, provider_subscription_id):
        return {"status": "cancelled", "id": provider_subscription_id}
    def verify_webhook(self, payload, signature, secret):
        # deterministic HMAC check; if secret == "mock_secret", require signature == HMAC
        if not secret: return False
        expected=hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

def get_payment_provider(name: str | None = None) -> PaymentProvider:
    # provider-neutral: only mock implemented; real Stripe/Razorpay would be separate adapter when credentials available
    return MockPaymentProvider()
