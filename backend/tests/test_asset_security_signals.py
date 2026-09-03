import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, JSON, String, DateTime, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.services.asset_security_signals import aggregate_security_signals_for_assets, get_project_security_summary
from app.services.asset_classification import is_public_ip

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

def test_finding_severity_aggregation():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    for sev in ["critical","high","medium","low","info","critical"]:
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity=sev, score=90 if sev=="critical" else 10))
    db.commit()
    sig=aggregate_security_signals_for_assets(db,[a])[a.id]
    fs=sig["finding_signal"]
    assert fs["total"]==6
    assert fs["critical"]==2
    assert fs["high"]==1
    assert fs["medium"]==1
    assert fs["low"]==1
    assert fs["info"]==1

def test_highest_severity():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="medium", score=50))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    fs=aggregate_security_signals_for_assets(db,[a])[a.id]["finding_signal"]
    assert fs["highest_severity"]=="high"

def test_highest_score():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=95))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[a])[a.id]["finding_signal"]["highest_score"]==95

def test_internet_facing_signal():
    db=_session()
    pid=str(uuid.uuid4())
    ip_pub=_mk_asset(db,pid,"ip","8.8.8.8")
    ip_priv=_mk_asset(db,pid,"ip","10.0.0.8")
    sig=aggregate_security_signals_for_assets(db,[ip_pub,ip_priv])
    assert sig[ip_pub.id]["exposure_signal"]["internet_facing"] is True
    assert sig[ip_priv.id]["exposure_signal"]["internet_facing"] is False

def test_externally_resolvable_signal():
    db=_session()
    pid=str(uuid.uuid4())
    d=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=d.id, target_asset_id=ip.id, relationship_type="resolves_to"))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[d])[d.id]["exposure_signal"]["externally_resolvable"] is True
    assert aggregate_security_signals_for_assets(db,[ip])[ip.id]["exposure_signal"]["externally_resolvable"] is False

def test_web_application_signal():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/")
    d=_mk_asset(db,pid,"domain","example.com")
    assert aggregate_security_signals_for_assets(db,[url])[url.id]["exposure_signal"]["web_application"] is True
    assert aggregate_security_signals_for_assets(db,[d])[d.id]["exposure_signal"]["web_application"] is False

def test_exposed_service_signal():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","443")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=ip.id, target_asset_id=port.id, relationship_type="exposes"))
    db.commit()
    sig=aggregate_security_signals_for_assets(db,[ip,port])
    assert sig[ip.id]["exposure_signal"]["exposed_service"] is True
    assert sig[port.id]["exposure_signal"]["exposed_service"] is True

def test_technology_count():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/")
    tech1=_mk_asset(db,pid,"technology","nginx")
    tech2=_mk_asset(db,pid,"technology","react")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech1.id, relationship_type="serves"))
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech2.id, relationship_type="serves"))
    db.commit()
    sig=aggregate_security_signals_for_assets(db,[url])[url.id]
    assert sig["technology_signal"]["technology_bearing"] is True
    assert sig["technology_signal"]["technology_count"]==2

def test_duplicate_technology_relationships():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/")
    tech=_mk_asset(db,pid,"technology","nginx")
    # duplicate same tech via two rels with different ids but same target should count once
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech.id, relationship_type="serves"))
    # Second rel with same target but different id - but unique constraint would prevent duplicate tuple, so we simulate duplicate by adding same target via different type? Instead add same tech but count distinct target_id should be 1
    # Add another distinct tech with same value but different id? For test, add same tech id again via separate rel with same target_id - will fail unique, so we test distinct count logic by adding two rels to same tech but with different relationship_type? Simpler: add two rels to same tech id with serves and uses? That would count distinct target once.
    # We'll just assert that duplicate rels don't double count distinct
    db.commit()
    # Manually test count distinct logic: if we had two rels to same tech, count should be 1. Our data has one rel, count 1. To simulate duplicate, we insert second with same target but different id (unique constraint would conflict on project,source,target,type) - so we use different type
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech.id, relationship_type="uses"))
    db.commit()
    sig=aggregate_security_signals_for_assets(db,[url])[url.id]
    # serves+uses to same tech should count as 1 distinct technology (since same target)
    assert sig["technology_signal"]["technology_count"]==1

def test_recent_change_count():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    now=datetime.now(timezone.utc)
    db.add(AssetChangeEvent(id=str(uuid.uuid4()), project_id=pid, asset_id=a.id, scan_id=str(uuid.uuid4()), change_type="new_asset", detected_at=now))
    db.add(AssetChangeEvent(id=str(uuid.uuid4()), project_id=pid, asset_id=a.id, scan_id=str(uuid.uuid4()), change_type="technology_changed", detected_at=now))
    db.commit()
    sig=aggregate_security_signals_for_assets(db,[a])[a.id]
    assert sig["change_signal"]["recently_changed"] is True
    assert sig["change_signal"]["recent_change_count"]==2

def test_old_change_excluded():
    db=_session()
    pid=str(uuid.uuid4())
    old=datetime.now(timezone.utc)-timedelta(days=30)
    a=_mk_asset(db,pid,"domain","example.com", last_seen_at=old, updated_at=old, created_at=old)
    db.add(AssetChangeEvent(id=str(uuid.uuid4()), project_id=pid, asset_id=a.id, scan_id=str(uuid.uuid4()), change_type="new_asset", detected_at=old))
    db.commit()
    sig=aggregate_security_signals_for_assets(db,[a])[a.id]
    assert sig["change_signal"]["recent_change_count"]==0
    assert sig["change_signal"]["recently_changed"] is False

def test_vulnerable_signal():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[a])[a.id]["posture"]["vulnerable"] is True
    db2=_session()
    pid2=str(uuid.uuid4())
    b=_mk_asset(db2,pid2,"domain","example.com")
    assert aggregate_security_signals_for_assets(db2,[b])[b.id]["posture"]["vulnerable"] is False

def test_critical_exposure():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[ip])[ip.id]["posture"]["critical_exposure"] is True
    # private ip with critical should not be critical_exposure
    db2=_session()
    pid2=str(uuid.uuid4())
    priv=_mk_asset(db2,pid2,"ip","10.0.0.8")
    db2.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=priv.id, scanner="nuclei", title="t", severity="critical", score=90))
    db2.commit()
    assert aggregate_security_signals_for_assets(db2,[priv])[priv.id]["posture"]["critical_exposure"] is False

def test_exposed_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[ip])[ip.id]["posture"]["exposed_vulnerable"] is True

def test_sensitive_exposed():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    # sensitive ip value? Use domain sensitive
    dom=_mk_asset(db,pid,"domain","admin.example.com")
    # need internet_facing for sensitive_exposed: admin domain that resolves to public ip
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=dom.id, target_asset_id=ip.id, relationship_type="resolves_to"))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[dom])[dom.id]["posture"]["sensitive_exposed"] is True
    # generic not sensitive
    dom2=_mk_asset(db,pid,"domain","example.com")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=dom2.id, target_asset_id=ip.id, relationship_type="resolves_to"))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[dom2])[dom2.id]["posture"]["sensitive_exposed"] is False

def test_changed_and_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com", updated_at=datetime.now(timezone.utc))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[a])[a.id]["posture"]["changed_and_vulnerable"] is True
    # old not changed
    db2=_session()
    pid2=str(uuid.uuid4())
    old=datetime.now(timezone.utc)-timedelta(days=30)
    b=_mk_asset(db2,pid2,"domain","example.com", last_seen_at=old, updated_at=old, created_at=old)
    db2.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=b.id, scanner="nuclei", title="t", severity="high", score=75))
    db2.commit()
    assert aggregate_security_signals_for_assets(db2,[b])[b.id]["posture"]["changed_and_vulnerable"] is False

def test_lifecycle_state():
    db=_session()
    pid=str(uuid.uuid4())
    for status in ["active","stale","inactive"]:
        a=_mk_asset(db,pid,"domain",f"{status}.example.com", status=status)
        assert aggregate_security_signals_for_assets(db,[a])[a.id]["lifecycle_signal"]["status"]==status

def test_project_isolation():
    db=_session()
    pid_a=str(uuid.uuid4())
    pid_b=str(uuid.uuid4())
    a1=_mk_asset(db,pid_a,"domain","example.com")
    a2=_mk_asset(db,pid_b,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a1.id, scanner="nuclei", title="t", severity="critical", score=90))
    ip_a=_mk_asset(db,pid_a,"ip","8.8.8.8")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid_a, source_asset_id=a1.id, target_asset_id=ip_a.id, relationship_type="resolves_to"))
    db.commit()
    sig_a=aggregate_security_signals_for_assets(db,[a1])[a1.id]
    sig_b=aggregate_security_signals_for_assets(db,[a2])[a2.id]
    assert sig_a["posture"]["vulnerable"] is True
    assert sig_a["posture"]["critical_exposure"] is True
    assert sig_b["posture"]["vulnerable"] is False
    assert sig_b["posture"]["critical_exposure"] is False
    assert sig_b["exposure_signal"]["internet_facing"] is False

def test_empty_asset():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","empty.example.com")
    sig=aggregate_security_signals_for_assets(db,[a])[a.id]
    assert sig["finding_signal"]["total"]==0
    assert sig["finding_signal"]["highest_severity"] is None
    assert sig["technology_signal"]["technology_count"]==0
    assert sig["change_signal"]["recent_change_count"]==0
    assert sig["posture"]["vulnerable"] is False

def test_multiple_findings():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    for sev,score in [("critical",90),("critical",95),("high",75),("info",5)]:
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity=sev, score=score))
    db.commit()
    fs=aggregate_security_signals_for_assets(db,[a])[a.id]["finding_signal"]
    assert fs["total"]==4
    assert fs["critical"]==2
    assert fs["highest_severity"]=="critical"
    assert fs["highest_score"]==95

def test_multiple_technologies():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/")
    for tech_name in ["nginx","react","wordpress"]:
        tech=_mk_asset(db,pid,"technology",tech_name)
        db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech.id, relationship_type="serves"))
    db.commit()
    assert aggregate_security_signals_for_assets(db,[url])[url.id]["technology_signal"]["technology_count"]==3

def test_batch_aggregation():
    db=_session()
    pid=str(uuid.uuid4())
    assets=[]
    for i in range(5):
        a=_mk_asset(db,pid,"domain",f"host{i}.example.com")
        assets.append(a)
        if i%2==0:
            db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    sigs=aggregate_security_signals_for_assets(db,assets)
    assert len(sigs)==5
    vulnerable=sum(1 for s in sigs.values() if s["posture"]["vulnerable"])
    assert vulnerable==3

def test_deterministic_repeated():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    s1=aggregate_security_signals_for_assets(db,[a])
    s2=aggregate_security_signals_for_assets(db,[a])
    assert s1==s2

def test_no_n_plus_one():
    db=_session()
    pid=str(uuid.uuid4())
    assets=[_mk_asset(db,pid,"domain",f"host{i}.example.com") for i in range(20)]
    import time
    start=time.time()
    sigs=aggregate_security_signals_for_assets(db,assets)
    elapsed=time.time()-start
    assert len(sigs)==20
    assert elapsed < 2.0

def test_project_summary():
    db=_session()
    pid=str(uuid.uuid4())
    # create 3 assets: 1 internet facing vulnerable, 1 web, 1 stale
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    url=_mk_asset(db,pid,"url","https://example.com/")
    stale=_mk_asset(db,pid,"domain","stale.example.com", status="stale")
    tech=_mk_asset(db,pid,"technology","nginx")
    db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=url.id, target_asset_id=tech.id, relationship_type="serves"))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    summary=get_project_security_summary(db,pid)
    assert summary["total_assets"]==4
    assert summary["internet_facing_assets"]>=1
    assert summary["vulnerable_assets"]==1
    assert summary["critical_assets"]==1
    assert summary["web_applications"]>=1
    assert summary["stale_assets"]==1

