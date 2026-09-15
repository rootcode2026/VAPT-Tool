"""Commercial — plan catalog, subscriptions, license, usage, billing — tenant-isolated, RLS, RBAC."""
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization

router = APIRouter(prefix="/api/v1", tags=["Commercial"])

# helper: super admin check
def _require_super_admin(user: User):
    if (user.role or "").lower() != "super_admin":
        # also check via organization_membership super_admin? For simplicity, check role
        raise HTTPException(status_code=403, detail="Super admin required")

def _require_org_member(organization_id: str, db: Session, user: User):
    from app.models.organization_membership import OrganizationMembership
    from app.api.deps import _is_super_admin
    if _is_super_admin(user):
        return
    mem=db.query(OrganizationMembership).filter(OrganizationMembership.organization_id==organization_id, OrganizationMembership.user_id==user.id, OrganizationMembership.status=="active").first()
    if not mem:
        raise HTTPException(status_code=403, detail="Organization membership required")

# Plans — public list + super admin CRUD
@router.get("/plans")
def list_plans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.services.commercial import list_plans as svc
    plans=svc(db, active_only=True)
    return {"plans": [{"id":p.id,"code":p.code,"name":p.name,"description":p.description,"active":p.active,"monthly_price":str(p.monthly_price) if p.monthly_price is not None else None,"annual_price":str(p.annual_price) if p.annual_price is not None else None,"currency":p.currency,"asset_limit":p.asset_limit,"user_limit":p.user_limit,"project_limit":p.project_limit,"scan_limit":p.scan_limit,"entitlements":p.entitlements,"limits":p.limits} for p in plans]}

@router.get("/admin/plans")
def admin_list_plans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_super_admin(current_user)
    from app.services.commercial import list_plans as svc
    plans=svc(db, active_only=False)
    return {"plans": [{"id":p.id,"code":p.code,"name":p.name,"active":p.active,"monthly_price":str(p.monthly_price) if p.monthly_price else None} for p in plans]}

@router.post("/admin/plans")
def admin_create_plan(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_super_admin(current_user)
    from app.models.commercial import Plan
    import uuid, decimal
    code=payload.get("code","").strip().lower()
    if not code: raise HTTPException(status_code=400, detail="code required")
    if db.query(Plan).filter(Plan.code==code).first():
        raise HTTPException(status_code=409, detail="Plan code exists")
    try:
        mp=payload.get("monthly_price")
        ap=payload.get("annual_price")
        mp_dec=decimal.Decimal(str(mp)) if mp is not None else None
        ap_dec=decimal.Decimal(str(ap)) if ap is not None else None
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid price")
    plan=Plan(id=str(uuid.uuid4()), code=code, name=payload.get("name",code.title()), description=payload.get("description"), active=payload.get("active",True), monthly_price=mp_dec, annual_price=ap_dec, currency=payload.get("currency","INR"), asset_limit=payload.get("asset_limit"), user_limit=payload.get("user_limit"), project_limit=payload.get("project_limit"), scan_limit=payload.get("scan_limit"), entitlements=payload.get("entitlements") or {}, limits=payload.get("limits") or {}, metadata_=payload.get("metadata") or {})
    db.add(plan); db.commit(); db.refresh(plan)
    # audit
    try:
        from app.services.audit import AuditService
        AuditService.record(db, event_type="PLAN_CREATED", action="PLAN_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="plan", resource_id=plan.id, metadata={"code": code})
        db.commit()
    except: pass
    return {"id": plan.id, "code": plan.code}

@router.patch("/admin/plans/{plan_id}")
def admin_update_plan(plan_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_super_admin(current_user)
    from app.models.commercial import Plan
    plan=db.query(Plan).filter(Plan.id==plan_id).first()
    if not plan: raise HTTPException(status_code=404, detail="Plan not found")
    for field in ("name","description","active","currency","asset_limit","user_limit","project_limit","scan_limit","entitlements","limits"):
        if field in payload:
            setattr(plan, field if field not in ("entitlements","limits") else field, payload[field])
    db.commit(); db.refresh(plan)
    return {"id": plan.id, "active": plan.active}

# Customer commercial — organization scoped, tenant-isolated
@router.get("/organizations/{organization_id}/billing/plan")
def get_current_plan(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.services.commercial import get_plan, get_plan_by_code
    from app.models.commercial import Subscription
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id, Subscription.status.in_(["trialing","active","past_due","grace_period"])).order_by(Subscription.created_at.desc()).first()
    if sub:
        plan=get_plan(db, sub.plan_id)
    else:
        plan=get_plan_by_code(db, "free")
    if not plan: raise HTTPException(status_code=404, detail="Plan not found")
    return {"plan": {"id": plan.id, "code": plan.code, "name": plan.name, "monthly_price": str(plan.monthly_price) if plan.monthly_price else None, "entitlements": plan.entitlements, "limits": plan.limits}}

@router.get("/organizations/{organization_id}/billing/subscription")
def get_subscription(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.models.commercial import Subscription
    sub=db.query(Subscription).filter(Subscription.organization_id==organization_id).order_by(Subscription.created_at.desc()).first()
    if not sub:
        return {"subscription": None}
    return {"subscription": {"id": sub.id, "plan_id": sub.plan_id, "status": sub.status, "billing_interval": sub.billing_interval, "renewal_date": sub.renewal_date.isoformat() if sub.renewal_date else None, "provider": sub.provider}}

@router.get("/organizations/{organization_id}/billing/license")
def get_license(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.services.commercial import validate_license
    lic=validate_license(db, organization_id)
    return {"license": lic}

@router.get("/organizations/{organization_id}/billing/entitlements")
def get_entitlements(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.services.commercial import get_entitlements
    return {"entitlements": get_entitlements(db, organization_id)}

@router.get("/organizations/{organization_id}/billing/usage")
def get_usage(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.services.commercial import usage_summary, get_limits
    return {"usage": usage_summary(db, organization_id), "limits": get_limits(db, organization_id)}

@router.get("/organizations/{organization_id}/billing/status")
def get_billing_status(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.services.commercial import validate_license
    lic=validate_license(db, organization_id)
    return {"status": lic.get("status"), "valid": lic.get("valid")}

# Subscription change — backend only, not frontend direct plan change (requires webhook verified)
@router.post("/organizations/{organization_id}/billing/subscription")
def create_sub(organization_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    # only org_admin can change plan
    from app.models.organization_membership import OrganizationMembership
    mem=db.query(OrganizationMembership).filter(OrganizationMembership.organization_id==organization_id, OrganizationMembership.user_id==current_user.id, OrganizationMembership.role=="org_admin", OrganizationMembership.status=="active").first()
    from app.api.deps import _is_super_admin
    if not mem and not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="org_admin required to change plan")
    from app.services.commercial import create_subscription
    try:
        sub=create_subscription(db, organization_id, payload.get("plan_code","starter"), payload.get("billing_interval","monthly"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"subscription_id": sub.id, "status": sub.status}

# Admin commercial overview
@router.get("/admin/commercial/subscriptions")
def admin_subs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_super_admin(current_user)
    from app.models.commercial import Subscription
    subs=db.query(Subscription).limit(100).all()
    return {"subscriptions": [{"id":s.id,"organization_id":s.organization_id,"plan_id":s.plan_id,"status":s.status} for s in subs]}

@router.get("/admin/commercial/licenses")
def admin_licenses(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_super_admin(current_user)
    from app.models.commercial import License
    lics=db.query(License).limit(100).all()
    return {"licenses": [{"id":l.id,"organization_id":l.organization_id,"status":l.status,"expires_at": l.expires_at.isoformat() if l.expires_at else None} for l in lics]}

@router.get("/admin/commercial/usage")
def admin_usage(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_super_admin(current_user)
    from app.models.commercial import UsageEvent
    rows=db.query(UsageEvent.organization_id, func.count(UsageEvent.id)).group_by(UsageEvent.organization_id).limit(100).all()
    return {"usage": [{"organization_id": r[0], "count": r[1]} for r in rows]}

# Checkout — creates provider checkout (Razorpay order or mock), not subscription directly
@router.post("/organizations/{organization_id}/billing/checkout")
def create_checkout(organization_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _require_org_member(organization_id, db, current_user)
    from app.models.organization_membership import OrganizationMembership
    mem=db.query(OrganizationMembership).filter(OrganizationMembership.organization_id==organization_id, OrganizationMembership.user_id==current_user.id, OrganizationMembership.role=="org_admin", OrganizationMembership.status=="active").first()
    from app.api.deps import _is_super_admin
    if not mem and not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="org_admin required")
    plan_code=str(payload.get("plan_code","")).strip().lower()
    interval=str(payload.get("billing_interval","monthly")).strip().lower()
    if not plan_code: raise HTTPException(status_code=400, detail="plan_code required")
    if interval not in ("monthly","annual"):
        raise HTTPException(status_code=400, detail="Invalid interval")
    from app.services.commercial import get_payment_provider
    try:
        provider=get_payment_provider()
        res=provider.create_checkout(organization_id, plan_code, interval)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return res

# Webhook — durable idempotency via payment_webhook_events, HMAC, replay-safe
@router.post("/webhooks/payment")
def payment_webhook(payload: dict, db: Session = Depends(get_db), x_webhook_signature: str | None = Header(None, alias="X-Webhook-Signature"), x_webhook_id: str | None = Header(None, alias="X-Webhook-Id"), x_razorpay_signature: str | None = Header(None, alias="X-Razorpay-Signature")):
    import hmac, hashlib, json, os, uuid
    # provider detection: Razorpay uses X-Razorpay-Signature
    sig=x_razorpay_signature or x_webhook_signature
    # choose secret based on provider
    secret=os.getenv("RAZORPAY_WEBHOOK_SECRET", "") or os.getenv("PAYMENT_WEBHOOK_SECRET", "mock_secret")
    # Razorpay webhook secret is separate; fallback to mock_secret
    body=json.dumps(payload, sort_keys=True).encode()
    # verify signature if provided
    if sig:
        # provider-specific verification via service
        from app.services.commercial import get_payment_provider
        try:
            provider=get_payment_provider()
            if not provider.verify_webhook(body, sig, secret):
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
        except HTTPException:
            raise
        except Exception:
            # generic HMAC fallback
            expected=hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, sig):
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
    else:
        # require signature in production
        if os.getenv("ENVIRONMENT","development").lower()=="production":
            raise HTTPException(status_code=401, detail="Missing webhook signature")
    # durable idempotency: provider_event_id = X-Webhook-Id or payload id/event_id
    wid=x_webhook_id or payload.get("id") or payload.get("event_id") or payload.get("entity") and str(payload.get("entity")) or str(uuid.uuid4())
    wid=str(wid).strip()[:100]
    provider_name=os.getenv("PAYMENT_PROVIDER","mock").lower() or "mock"
    # check DB for existing
    from app.models.commercial import PaymentWebhookEvent
    existing=db.query(PaymentWebhookEvent).filter(PaymentWebhookEvent.provider==provider_name, PaymentWebhookEvent.provider_event_id==wid).first()
    if existing:
        return {"status": "already_processed", "event_id": wid}
    # insert durable record
    org_id=payload.get("organization_id") or payload.get("org_id") or (payload.get("payload",{}).get("payment",{}).get("entity",{}).get("notes",{}).get("organization_id") if isinstance(payload.get("payload"), dict) else None)
    try:
        evt=PaymentWebhookEvent(id=str(uuid.uuid4()), provider=provider_name, provider_event_id=wid, organization_id=org_id if org_id and len(str(org_id))==36 else None, event_type=payload.get("type") or payload.get("event"), payload=payload)
        db.add(evt); db.flush()
    except Exception:
        try: db.rollback()
        except: pass
        # on unique violation, treat as already processed
        dup=db.query(PaymentWebhookEvent).filter(PaymentWebhookEvent.provider==provider_name, PaymentWebhookEvent.provider_event_id==wid).first()
        if dup:
            return {"status": "already_processed", "event_id": wid}
    # audit webhook
    try:
        from app.services.audit import AuditService
        AuditService.record(db, event_type="PAYMENT_WEBHOOK", action="PAYMENT_WEBHOOK", result="SUCCESS", actor_user_id=None, organization_id=org_id or "unknown", resource_type="payment", resource_id=wid, metadata={"event_type": payload.get("type")})
    except: pass
    # handle subscription status deterministically (idempotent)
    if org_id and payload.get("type") in ("subscription.active","subscription.past_due","subscription.cancelled","payment.captured","order.paid"):
        from app.models.commercial import Subscription, License
        sub=db.query(Subscription).filter(Subscription.organization_id==org_id).order_by(Subscription.created_at.desc()).first()
        if sub:
            mapping={"subscription.active":"active","subscription.past_due":"past_due","subscription.cancelled":"cancelled","payment.captured":"active","order.paid":"active"}
            new_status=mapping.get(payload.get("type"), sub.status)
            if sub.status != new_status:
                sub.status=new_status
                # update license
                lic=db.query(License).filter(License.organization_id==org_id, License.subscription_id==sub.id).order_by(License.created_at.desc()).first()
                if lic:
                    lic.status="active" if new_status=="active" else lic.status
                # handle out-of-order: if active after cancelled, prefer latest
            db.flush()
    try:
        db.commit()
    except Exception:
        try: db.rollback()
        except: pass
    return {"status": "processed", "event_id": wid}
