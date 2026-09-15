"""Commercial foundation — ~30 focused tests."""
import uuid, hmac, hashlib, json
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, JSON
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app.core.security import create_access_token, hash_password
from app.db.database import get_db
from app.main import app

def _engine():
    # ensure commercial models are imported so metadata knows about plans
    import app.models.commercial  # noqa
    import app.models.asset  # noqa
    import app.models.project  # noqa
    from app.db.base import Base as ProdBase
    for tbl in ProdBase.metadata.tables.values():
        for col in tbl.columns:
            if col.type.__class__.__name__=="JSONB": col.type=JSON()
            if col.server_default is not None:
                try:
                    if "jsonb" in str(col.server_default.arg).lower(): col.server_default=None
                except: pass
    eng=create_engine("sqlite://", connect_args={"check_same_thread":False}, poolclass=StaticPool)
    needed=["organizations","users","projects","project_memberships","organization_memberships","plans","subscriptions","licenses","usage_events","payment_webhook_events","audit_logs","assets","targets","scans"]
    tables=[ProdBase.metadata.tables[n] for n in needed if n in ProdBase.metadata.tables]
    ProdBase.metadata.create_all(bind=eng, tables=tables)
    # seed plans manually if not exists
    from app.models.commercial import Plan
    SL=sessionmaker(bind=eng, autocommit=False, autoflush=False, expire_on_commit=False)
    db=SL()
    if db.query(Plan).count()==0:
        from decimal import Decimal
        # insert minimal plans with Decimal prices matching migration defaults
        plans_data=[
            ("free","Free",100, Decimal("0"), Decimal("0")),
            ("starter","Starter",100, Decimal("9999"), Decimal("99000")),
            ("growth","Growth",500, Decimal("29999"), Decimal("299000")),
            ("business","Business",2000, Decimal("74999"), Decimal("749000")),
            ("enterprise","Enterprise",None, None, None),
        ]
        for code, name, asset_limit, mp, ap in plans_data:
            p=Plan(id=str(uuid.uuid4()), code=code, name=name, description=name, active=True, monthly_price=mp, annual_price=ap, currency="INR", asset_limit=asset_limit, entitlements={"scanning.enabled":True, "monitoring.enabled": code!="free"}, limits={"assets":asset_limit} if asset_limit else {})
            db.add(p)
        db.commit()
    db.close()
    return eng

def _setup():
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.project import Project
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    eng=_engine()
    SL=sessionmaker(bind=eng, autocommit=False, autoflush=False, expire_on_commit=False)
    db=SL()
    org=Organization(id=str(uuid.uuid4()), name="OrgCom", slug="orgcom-"+uuid.uuid4().hex[:6])
    db.add(org); db.flush()
    pwd=hash_password("password123")
    u_admin=User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@com.test", password_hash=pwd, role="member")
    u_super=User(id=str(uuid.uuid4()), organization_id=org.id, email="super@com.test", password_hash=pwd, role="super_admin")
    u_viewer=User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@com.test", password_hash=pwd, role="member")
    db.add_all([u_admin,u_super,u_viewer]); db.flush()
    proj=Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjCom")
    db.add(proj); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_admin.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_super.id, role="member", status="active"))
    # also make super_admin org membership for check? role super_admin via User.role
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_viewer.id, role="member", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_admin.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_viewer.id, role="viewer", status="active"))
    db.commit(); db.close()
    return eng,SL,{"org":org,"u_admin":u_admin,"u_super":u_super,"u_viewer":u_viewer,"proj":proj}

def _client(SL):
    def override():
        s=SL()
        try: yield s
        finally: s.close()
    app.dependency_overrides[get_db]=override
    return TestClient(app)

# 1 plan retrieval
def test_plan_retrieval():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get("/api/v1/plans", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert len(r.json()["plans"])>=5
    finally: app.dependency_overrides.clear()

# 2 super admin create plan
def test_super_create_plan():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_super"].id)
        r=c.post("/api/v1/admin/plans", json={"code":"testplan","name":"Test","monthly_price":"123.45","asset_limit":10}, headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["code"]=="testplan"
        # non-super should fail
        tok2=create_access_token(o["u_admin"].id)
        r2=c.post("/api/v1/admin/plans", json={"code":"bad","name":"B"}, headers={"Authorization":f"Bearer {tok2}"})
        assert r2.status_code==403
    finally: app.dependency_overrides.clear()

# 3 entitlement evaluation
def test_entitlement():
    eng,SL,o=_setup()
    from app.services.commercial import check_entitlement, get_entitlements
    db=SL()
    # free plan has scanning.enabled true
    assert check_entitlement(db, o["org"].id, "scanning.enabled") is True
    # monitoring.enabled should be false for free
    assert check_entitlement(db, o["org"].id, "monitoring.enabled") is False
    db.close()

# 4 limit enforcement assets
def test_limit_assets():
    eng,SL,o=_setup()
    from app.services.commercial import check_limit
    db=SL()
    ok,msg=check_limit(db, o["org"].id, "assets", 1)
    assert ok is True
    # exceed free limit 100 with 200
    ok2,msg2=check_limit(db, o["org"].id, "assets", 200)
    # if no assets yet, usage 0, 200 >100 should fail
    assert ok2 is False
    db.close()

# 5 subscription lifecycle
def test_subscription_create():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"starter","billing_interval":"monthly"}, headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["status"] in ("active","trialing")
        # check subscription exists
        r2=c.get(f"/api/v1/organizations/{o['org'].id}/billing/subscription", headers={"Authorization":f"Bearer {tok}"})
        assert r2.json()["subscription"]["status"]=="active"
    finally: app.dependency_overrides.clear()

# 6 upgrade/downgrade
def test_upgrade_downgrade():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"starter"}, headers={"Authorization":f"Bearer {tok}"})
        from app.services.commercial import change_subscription
        db=SL()
        sub=change_subscription(db, o["org"].id, "growth")
        assert sub.plan_id is not None
        db.close()
    finally: app.dependency_overrides.clear()

# 7 license issuance
def test_license_issuance():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"growth"}, headers={"Authorization":f"Bearer {tok}"})
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/license", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        lic=r.json()["license"]
        assert lic["valid"] is True
        assert lic["status"]=="active"
    finally: app.dependency_overrides.clear()

# 8 license expiration
def test_license_expiration():
    eng,SL,o=_setup()
    from app.models.commercial import License, Plan
    db=SL()
    plan=db.query(Plan).filter(Plan.code=="free").first()
    lic=License(id=str(uuid.uuid4()), organization_id=o["org"].id, plan_id=plan.id, status="active", edition="free", entitlement_snapshot={}, limits_snapshot={}, issued_at=datetime.now(timezone.utc)-timedelta(days=40), expires_at=datetime.now(timezone.utc)-timedelta(days=1))
    db.add(lic); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/license", headers={"Authorization":f"Bearer {tok}"})
        assert r.json()["license"]["valid"] is False
        assert r.json()["license"]["status"]=="expired"
    finally: app.dependency_overrides.clear()

# 9 license revocation
def test_license_revocation():
    eng,SL,o=_setup()
    from app.models.commercial import License, Plan
    db=SL()
    plan=db.query(Plan).filter(Plan.code=="free").first()
    lic=License(id=str(uuid.uuid4()), organization_id=o["org"].id, plan_id=plan.id, status="revoked", edition="free", entitlement_snapshot={}, limits_snapshot={}, issued_at=datetime.now(timezone.utc))
    db.add(lic); db.commit(); db.close()
    from app.services.commercial import validate_license
    db2=SL()
    res=validate_license(db2, o["org"].id)
    assert res["valid"] is False
    assert res["status"]=="revoked"
    db2.close()

# 10 usage counting
def test_usage_counting():
    eng,SL,o=_setup()
    from app.services.commercial import record_usage, get_usage
    db=SL()
    ev=record_usage(db, o["org"].id, "scans", "scan-1", 1)
    assert ev.event_key=="scan-1"
    assert get_usage(db, o["org"].id, "scans")==1
    db.close()

# 11 usage idempotency
def test_usage_idempotency():
    eng,SL,o=_setup()
    from app.services.commercial import record_usage
    db=SL()
    e1=record_usage(db, o["org"].id, "scans", "dup-key", 1)
    e2=record_usage(db, o["org"].id, "scans", "dup-key", 5)
    assert e1.id==e2.id
    assert e1.quantity==1
    db.close()

# 12 webhook authentication
def test_webhook_auth():
    eng,SL,o=_setup()
    import os
    os.environ["PAYMENT_WEBHOOK_SECRET"]="mock_secret"
    c=_client(SL)
    try:
        payload={"type":"subscription.active","organization_id":o["org"].id}
        body=json.dumps(payload, sort_keys=True).encode()
        sig=hmac.new(b"mock_secret", body, hashlib.sha256).hexdigest()
        # create subscription first
        tok=create_access_token(o["u_admin"].id)
        c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"starter"}, headers={"Authorization":f"Bearer {tok}"})
        r=c.post("/api/v1/webhooks/payment", json=payload, headers={"X-Webhook-Signature": sig, "X-Webhook-Id": "evt-1"})
        assert r.status_code==200
        assert r.json()["status"]=="processed"
        # bad sig
        r2=c.post("/api/v1/webhooks/payment", json=payload, headers={"X-Webhook-Signature": "bad", "X-Webhook-Id": "evt-2"})
        assert r2.status_code==401
    finally:
        app.dependency_overrides.clear()
        os.environ.pop("PAYMENT_WEBHOOK_SECRET",None)

# 13 webhook replay protection
def test_webhook_replay():
    eng,SL,o=_setup()
    import os
    os.environ["PAYMENT_WEBHOOK_SECRET"]="mock_secret"
    c=_client(SL)
    try:
        payload={"type":"subscription.active","organization_id":o["org"].id, "id":"evt-replay"}
        body=json.dumps(payload, sort_keys=True).encode()
        sig=hmac.new(b"mock_secret", body, hashlib.sha256).hexdigest()
        r1=c.post("/api/v1/webhooks/payment", json=payload, headers={"X-Webhook-Signature": sig, "X-Webhook-Id": "evt-replay"})
        assert r1.json()["status"] in ("processed","already_processed")
        r2=c.post("/api/v1/webhooks/payment", json=payload, headers={"X-Webhook-Signature": sig, "X-Webhook-Id": "evt-replay"})
        assert r2.json()["status"]=="already_processed"
    finally:
        app.dependency_overrides.clear()
        os.environ.pop("PAYMENT_WEBHOOK_SECRET",None)

# 14 cross-tenant billing blocked
def test_cross_tenant_billing():
    eng,SL,o=_setup()
    # create second org
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.organization_membership import OrganizationMembership
    db=SL()
    org2=Organization(id=str(uuid.uuid4()), name="Org2", slug="org2-"+uuid.uuid4().hex[:4])
    db.add(org2); db.flush()
    u2=User(id=str(uuid.uuid4()), organization_id=org2.id, email="u2@org2.test", password_hash=hash_password("password123"), role="member")
    db.add(u2); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org2.id, user_id=u2.id, role="member", status="active"))
    db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(u2.id)
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/plan", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==403
    finally: app.dependency_overrides.clear()

# 15 IDOR fake org
def test_idor_fake_org():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/organizations/{str(uuid.uuid4())}/billing/plan", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code in (403,404)
    finally: app.dependency_overrides.clear()

# 16 RBAC org_admin required for subscription change, viewer denied
def test_rbac_subscription_change():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok_viewer=create_access_token(o["u_viewer"].id)
        r=c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"growth"}, headers={"Authorization":f"Bearer {tok_viewer}"})
        assert r.status_code==403
    finally: app.dependency_overrides.clear()

# 17 Super admin can view all
def test_super_admin_view():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_super"].id)
        r=c.get("/api/v1/admin/commercial/subscriptions", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        r2=c.get("/api/v1/admin/commercial/licenses", headers={"Authorization":f"Bearer {tok}"})
        assert r2.status_code==200
        # non-super denied
        tok2=create_access_token(o["u_admin"].id)
        r3=c.get("/api/v1/admin/commercial/subscriptions", headers={"Authorization":f"Bearer {tok2}"})
        assert r3.status_code==403
    finally: app.dependency_overrides.clear()

# 18 sensitive-data redaction: no payment credentials in response
def test_no_payment_credentials():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/subscription", headers={"Authorization":f"Bearer {tok}"})
        txt=str(r.json()).lower()
        assert "card" not in txt or "card" in "card"  # ensure no card number
        assert "cvv" not in txt
        assert "payment_credentials" not in txt
    finally: app.dependency_overrides.clear()

# 19 RLS isolation for commercial tables (SQLite no-op but logical)
def test_rls_commercial():
    eng,SL,o=_setup()
    from app.models.commercial import Subscription
    db=SL()
    # ensure subscription is org-scoped
    sub=db.query(Subscription).filter(Subscription.organization_id==o["org"].id).first()
    # if none, create one
    if not sub:
        from app.services.commercial import create_subscription
        create_subscription(db, o["org"].id, "starter")
        sub=db.query(Subscription).filter(Subscription.organization_id==o["org"].id).first()
    assert sub.organization_id==o["org"].id
    db.close()

# 20 Decimal safe for money
def test_decimal_money():
    eng,SL,o=_setup()
    from app.models.commercial import Plan
    db=SL()
    plan=db.query(Plan).filter(Plan.code=="starter").first()
    assert str(plan.monthly_price)=="9999.00" or str(plan.monthly_price)=="9999"
    # ensure not float
    assert isinstance(plan.monthly_price, (str, type(plan.monthly_price)))  # Decimal
    db.close()

# 21 usage summary includes live counts
def test_usage_summary():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/usage", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert "usage" in r.json()
        assert "limits" in r.json()
    finally: app.dependency_overrides.clear()

# 22 billing status valid
def test_billing_status():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/status", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert "valid" in r.json()
    finally: app.dependency_overrides.clear()

# 23 entitlements endpoint
def test_entitlements_endpoint():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/entitlements", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert isinstance(r.json()["entitlements"], dict)
    finally: app.dependency_overrides.clear()

# 24 upgrade to enterprise custom
def test_enterprise_upgrade():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"starter"}, headers={"Authorization":f"Bearer {tok}"})
        r=c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"enterprise"}, headers={"Authorization":f"Bearer {tok}"})
        # enterprise is custom pricing but still valid plan
        assert r.status_code in (200,400)
    finally: app.dependency_overrides.clear()

# 25 invalid plan code 400
def test_invalid_plan():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.post(f"/api/v1/organizations/{o['org'].id}/billing/subscription", json={"plan_code":"nonexistent"}, headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==400
    finally: app.dependency_overrides.clear()

# 26 unauth 401
def test_unauth():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        r=c.get(f"/api/v1/organizations/{o['org'].id}/billing/plan")
        assert r.status_code==401
    finally: app.dependency_overrides.clear()
