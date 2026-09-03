import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, JSON, String, DateTime, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.services.asset_contextual_risk import (
    aggregate_contextual_risk_for_assets,
    contextual_risk_from_signals,
    FACTOR_DEFS,
)
from app.services.asset_security_signals import aggregate_security_signals_for_assets

class Base(DeclarativeBase):
    pass

class Asset(Base):
    __tablename__="assets"
    __table_args__=(UniqueConstraint("project_id","asset_type","value",name="uq"),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    project_id:Mapped[str]=mapped_column(String(36))
    asset_type:Mapped[str]=mapped_column(String(50))
    value:Mapped[str]=mapped_column(String(1024))
    status:Mapped[str]=mapped_column(String(20),default="active")
    extra_data:Mapped[dict]=mapped_column("metadata", JSON, default=dict)
    first_seen_at:Mapped[datetime|None]=mapped_column(DateTime,nullable=True)
    last_seen_at:Mapped[datetime|None]=mapped_column(DateTime,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
    updated_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
    first_seen_scan_id:Mapped[str|None]=mapped_column(String(36),nullable=True)
    last_seen_scan_id:Mapped[str|None]=mapped_column(String(36),nullable=True)

class AssetRelationship(Base):
    __tablename__="asset_relationships"
    __table_args__=(UniqueConstraint("project_id","source_asset_id","target_asset_id","relationship_type",name="uq2"),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    project_id:Mapped[str]=mapped_column(String(36))
    source_asset_id:Mapped[str]=mapped_column(String(36))
    target_asset_id:Mapped[str]=mapped_column(String(36))
    relationship_type:Mapped[str]=mapped_column(String(50))
    extra_data:Mapped[dict]=mapped_column("metadata", JSON, default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
    updated_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)

class Finding(Base):
    __tablename__="findings"
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    scan_id:Mapped[str]=mapped_column(String(36))
    target_id:Mapped[str]=mapped_column(String(36))
    asset_id:Mapped[str|None]=mapped_column(String(36),nullable=True)
    scanner:Mapped[str]=mapped_column(String(50))
    title:Mapped[str]=mapped_column(String(500))
    severity:Mapped[str]=mapped_column(String(20),default="info")
    score:Mapped[int|None]=mapped_column(Integer,nullable=True)
    extra_data:Mapped[dict]=mapped_column("metadata", JSON, default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
    status:Mapped[str]=mapped_column(String(20),default="open")
    description:Mapped[str|None]=mapped_column(String(500),nullable=True)
    evidence:Mapped[str|None]=mapped_column(String(500),nullable=True)
    remediation:Mapped[str|None]=mapped_column(String(500),nullable=True)
    cve:Mapped[str|None]=mapped_column(String(50),nullable=True)
    cwe:Mapped[str|None]=mapped_column(String(50),nullable=True)

class AssetChangeEvent(Base):
    __tablename__="asset_change_events"
    __table_args__=(UniqueConstraint("scan_id","asset_id","change_type",name="uq3"),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    project_id:Mapped[str]=mapped_column(String(36))
    asset_id:Mapped[str]=mapped_column(String(36))
    scan_id:Mapped[str]=mapped_column(String(36))
    change_type:Mapped[str]=mapped_column(String(50))
    detected_at:Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
    extra_data:Mapped[dict]=mapped_column("metadata", JSON, default=dict)
    previous_state:Mapped[dict|None]=mapped_column(JSON,nullable=True)
    current_state:Mapped[dict|None]=mapped_column(JSON,nullable=True)

def _session():
    engine=create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

def _mk_asset(db, project_id, atype, value, **kw):
    a=Asset(id=str(uuid.uuid4()), project_id=project_id, asset_type=atype, value=value, **kw)
    db.add(a)
    db.commit()
    return a

def test_no_findings_informational():
    db=_session()
    pid=str(uuid.uuid4())
    old=datetime.now(timezone.utc)-timedelta(days=30)
    a=_mk_asset(db,pid,"domain","example.com", last_seen_at=old, updated_at=old, created_at=old)
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    assert sig["priority"]=="informational"
    assert sig["risk_factors"]==[]

def test_critical_finding_factor():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ip","10.0.0.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    assert any(f["code"]=="CRITICAL_FINDING" and f["severity"]=="critical" for f in sig["risk_factors"])
    # private so not critical priority
    assert sig["priority"] in ("medium","high","critical")

def test_critical_internet_facing_critical_priority():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[ip])[ip.id]
    assert sig["priority"]=="critical"
    assert any(f["code"]=="CRITICAL_EXPOSURE" for f in sig["risk_factors"])
    assert "Critical finding affects an internet-facing asset." in sig["explanation"]

def test_high_internet_facing_high_priority():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[ip])[ip.id]
    assert sig["priority"]=="high"

def test_vulnerable_private_lower_priority():
    db=_session()
    pid=str(uuid.uuid4())
    priv=_mk_asset(db,pid,"ip","10.0.0.8")
    pub=_mk_asset(db,pid,"ip","8.8.8.8")
    for a in [priv, pub]:
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    sig_priv=aggregate_contextual_risk_for_assets(db,[priv])[priv.id]
    sig_pub=aggregate_contextual_risk_for_assets(db,[pub])[pub.id]
    # pub should be higher priority than private
    order={"critical":0,"high":1,"medium":2,"low":3,"informational":4}
    assert order[sig_pub["priority"]] < order[sig_priv["priority"]]

def test_sensitive_internet_facing():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    dom=_mk_asset(db,pid,"domain","admin.example.com")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=dom.id, target_asset_id=ip.id, relationship_type="resolves_to"))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[dom])[dom.id]
    assert any(f["code"]=="SENSITIVE_EXPOSED" for f in sig["risk_factors"])
    assert "Potentially sensitive asset is internet-facing." in sig["explanation"]

def test_recently_changed_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com", updated_at=datetime.now(timezone.utc))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="medium", score=50))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    assert any(f["code"]=="CHANGED_AND_VULNERABLE" for f in sig["risk_factors"])
    assert sig["priority"]=="medium"

def test_exposed_service_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","10.0.0.8")
    port=_mk_asset(db,pid,"port","443")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=ip.id, target_asset_id=port.id, relationship_type="exposes"))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[ip])[ip.id]
    assert any(f["code"]=="EXPOSED_SERVICE" for f in sig["risk_factors"])
    assert sig["priority"] in ("medium","high","critical")

def test_multiple_factors():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    dom=_mk_asset(db,pid,"domain","admin.example.com")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=dom.id, target_asset_id=ip.id, relationship_type="resolves_to"))
    # need tech for dom to test multiple
    tech=_mk_asset(db,pid,"technology","nginx")
    url=_mk_asset(db,pid,"url","https://admin.example.com/")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech.id, relationship_type="serves"))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=dom.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[dom])[dom.id]
    codes={f["code"] for f in sig["risk_factors"]}
    assert "CRITICAL_FINDING" in codes
    assert "INTERNET_FACING" in codes
    assert "SENSITIVE_EXPOSED" in codes

def test_factor_deduplication():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=95))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    codes=[f["code"] for f in sig["risk_factors"]]
    assert codes.count("CRITICAL_FINDING")==1

def test_deterministic_ordering():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    sig1=aggregate_contextual_risk_for_assets(db,[ip])[ip.id]["risk_factors"]
    sig2=aggregate_contextual_risk_for_assets(db,[ip])[ip.id]["risk_factors"]
    assert sig1==sig2
    # check sorted by severity then code
    severities=[f["severity"] for f in sig1]
    assert severities==sorted(severities, key=lambda s: {"critical":0,"high":1,"medium":2,"low":3,"informational":4}[s])

def test_deterministic_repeated():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    s1=aggregate_contextual_risk_for_assets(db,[a])
    s2=aggregate_contextual_risk_for_assets(db,[a])
    assert s1==s2

def test_project_isolation():
    db=_session()
    pid_a=str(uuid.uuid4())
    pid_b=str(uuid.uuid4())
    old=datetime.now(timezone.utc)-timedelta(days=30)
    a1=_mk_asset(db,pid_a,"domain","admin.example.com")
    a2=_mk_asset(db,pid_b,"domain","admin.example.com", last_seen_at=old, updated_at=old, created_at=old)
    ip_a=_mk_asset(db,pid_a,"ip","8.8.8.8")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid_a, source_asset_id=a1.id, target_asset_id=ip_a.id, relationship_type="resolves_to"))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a1.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    sig_a=aggregate_contextual_risk_for_assets(db,[a1])[a1.id]
    sig_b=aggregate_contextual_risk_for_assets(db,[a2])[a2.id]
    assert sig_a["priority"]=="critical"
    # a2 is recent? we set old, so no recently_changed, and not sensitive exposed? sensitive but not internet_facing, so informational
    assert sig_b["priority"]=="informational"
    # a2 has sensitive but not internet_facing, so only SENSITIVE_ASSET, but we made old, so no RECENTLY_CHANGED
    # Actually sensitive alone gives low severity factor, but priority informational still? Check: sensitive alone not in priority rules, so informational but factors include SENSITIVE_ASSET
    # So we check not critical
    assert not any(f["code"]=="CRITICAL_EXPOSURE" for f in sig_b["risk_factors"])

def test_inactive_asset_behavior():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com", status="inactive")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    # inactive still counts as vulnerable, but lifecycle should be inactive
    assert sig["context"]["lifecycle_context"]["status"]=="inactive"
    assert sig["priority"] in ("critical","high","medium")

def test_stale_asset_behavior():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com", status="stale")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    assert sig["context"]["lifecycle_context"]["status"]=="stale"

def test_empty_asset():
    db=_session()
    pid=str(uuid.uuid4())
    old=datetime.now(timezone.utc)-timedelta(days=30)
    a=_mk_asset(db,pid,"domain","empty.example.com", last_seen_at=old, updated_at=old, created_at=old)
    sig=aggregate_contextual_risk_for_assets(db,[a])[a.id]
    assert sig["priority"]=="informational"
    assert sig["explanation"]=="No significant contextual risk signals."
    assert sig["risk_factors"]==[]

def test_batch_contextual():
    db=_session()
    pid=str(uuid.uuid4())
    assets=[]
    for i in range(5):
        atype="ip" if i%2==0 else "domain"
        val=f"8.8.4.{i+1}" if atype=="ip" else f"host{i}.example.com"
        a=_mk_asset(db,pid,atype,val)
        assets.append(a)
        if i%2==0:
            db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    sigs=aggregate_contextual_risk_for_assets(db,assets)
    assert len(sigs)==5
    critical=sum(1 for s in sigs.values() if s["priority"]=="critical")
    assert critical>=2

def test_no_n_plus_one():
    db=_session()
    pid=str(uuid.uuid4())
    assets=[_mk_asset(db,pid,"domain",f"host{i}.example.com") for i in range(20)]
    import time
    start=time.time()
    sigs=aggregate_contextual_risk_for_assets(db,assets)
    elapsed=time.time()-start
    assert len(sigs)==20
    assert elapsed < 2.0

def test_api_contains_contextual_risk():
    from app.schemas.asset import AssetDetailResponse, ContextualRisk
    payload=AssetDetailResponse.model_validate({
        "id":"a1","project_id":"p1","asset_type":"domain","value":"example.com","status":"active",
        "relationships":[],"findings":[],"security_summary":{}, "classifications":{}, "security_signals":{}, "contextual_risk": {"priority":"high","risk_factors":[{"code":"HIGH_FINDING","severity":"high","description":"x"}],"explanation":"x","context":{}}
    }).model_dump()
    assert payload["contextual_risk"]["priority"]=="high"
    assert "risk_factors" in payload["contextual_risk"]

def test_existing_fields_intact():
    from app.schemas.asset import AssetDetailResponse
    data={"id":"a1","project_id":"p1","asset_type":"domain","value":"example.com","status":"active","relationships":[],"findings":[],"security_summary":{"total_findings":1},"classifications":{"internet_facing":True},"security_signals":{"finding_signal":{"total":1}},"contextual_risk":{"priority":"high"}}
    obj=AssetDetailResponse.model_validate(data)
    assert obj.security_summary.total_findings==1
    assert obj.classifications.internet_facing is True
    assert obj.security_signals.finding_signal.total==1
    assert obj.contextual_risk.priority=="high"
