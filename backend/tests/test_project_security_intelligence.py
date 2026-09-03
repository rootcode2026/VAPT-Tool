import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, JSON, String, DateTime, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.services.project_security_intelligence import get_project_security_intelligence_summary

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

def _mk_asset(db, pid, atype, value, **kw):
    a=Asset(id=str(uuid.uuid4()), project_id=pid, asset_type=atype, value=value, **kw)
    db.add(a)
    db.commit()
    return a

def _mk_rel(db, pid, src, dst, rtype):
    r=AssetRelationship(id=str(uuid.uuid4()), project_id=pid, source_asset_id=src, target_asset_id=dst, relationship_type=rtype)
    db.add(r)
    db.commit()
    return r

def test_empty_project():
    db=_session()
    pid=str(uuid.uuid4())
    s=get_project_security_intelligence_summary(db, pid)
    assert s["total_assets"]==0
    assert s["attack_path_count"]==0
    assert s["attack_paths_truncated"] is False
    assert s["highest_contextual_priority"] is None
    for k in ["internet_facing_assets","vulnerable_assets","critical_assets"]:
        assert s[k]==0

def test_total_asset_count():
    db=_session()
    pid=str(uuid.uuid4())
    for i in range(3):
        _mk_asset(db,pid,"domain",f"host{i}.example.com")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["total_assets"]==3

def test_internet_facing_count():
    db=_session()
    pid=str(uuid.uuid4())
    ip_pub=_mk_asset(db,pid,"ip","8.8.8.8")
    ip_priv=_mk_asset(db,pid,"ip","10.0.0.8")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["internet_facing_assets"]==1

def test_externally_resolvable_count():
    db=_session()
    pid=str(uuid.uuid4())
    d=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,d.id,ip.id,"resolves_to")
    _mk_asset(db,pid,"domain","other.com")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["externally_resolvable_assets"]==1

def test_web_application_count():
    db=_session()
    pid=str(uuid.uuid4())
    _mk_asset(db,pid,"url","https://example.com/")
    _mk_asset(db,pid,"domain","example.com")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["web_application_assets"]==1
    assert s["web_applications"]==1

def test_exposed_service_count():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","443")
    _mk_rel(db,pid,ip.id,port.id,"exposes")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["exposed_service_assets"]==2  # ip and port both exposed
    assert s["exposed_services"]==2

def test_vulnerable_asset_count():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert get_project_security_intelligence_summary(db,pid)["vulnerable_assets"]==1

def test_critical_asset_distinct_count():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    for _ in range(3):
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    s=get_project_security_intelligence_summary(db,pid)
    assert s["critical_assets"]==1
    assert s["vulnerable_assets"]==1

def test_high_asset_distinct_count():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    b=_mk_asset(db,pid,"domain","other.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=b.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert get_project_security_intelligence_summary(db,pid)["high_assets"]==2

def test_medium_low_counts():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","a.example.com")
    b=_mk_asset(db,pid,"domain","b.example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="medium", score=50))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=b.id, scanner="nuclei", title="t", severity="low", score=25))
    db.commit()
    s=get_project_security_intelligence_summary(db,pid)
    assert s["medium_assets"]==1
    assert s["low_assets"]==1

def test_technology_bearing_count():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/")
    tech=_mk_asset(db,pid,"technology","nginx")
    _mk_rel(db,pid,url.id,tech.id,"serves")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["technology_bearing_assets"]==1

def test_sensitive_count():
    db=_session()
    pid=str(uuid.uuid4())
    _mk_asset(db,pid,"subdomain","admin.example.com")
    _mk_asset(db,pid,"domain","example.com")
    assert get_project_security_intelligence_summary(db,pid)["sensitive_assets"]==1

def test_recently_changed_count():
    db=_session()
    pid=str(uuid.uuid4())
    _mk_asset(db,pid,"domain","example.com", updated_at=datetime.now(timezone.utc))
    old=datetime.now(timezone.utc)-timedelta(days=30)
    _mk_asset(db,pid,"domain","old.example.com", updated_at=old, created_at=old, last_seen_at=old)
    assert get_project_security_intelligence_summary(db,pid)["recently_changed_assets"]==1

def test_stale_inactive_counts():
    db=_session()
    pid=str(uuid.uuid4())
    _mk_asset(db,pid,"domain","stale.example.com", status="stale")
    _mk_asset(db,pid,"domain","inactive.example.com", status="inactive")
    _mk_asset(db,pid,"domain","active.example.com", status="active")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["stale_assets"]==1
    assert s["inactive_assets"]==1

def test_critical_exposure_count():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    assert get_project_security_intelligence_summary(db,pid)["critical_exposure_assets"]==1

def test_exposed_vulnerable_count():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert get_project_security_intelligence_summary(db,pid)["exposed_vulnerable_assets"]==1

def test_sensitive_exposed_count():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","admin.example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    s=get_project_security_intelligence_summary(db,pid)
    assert s["sensitive_exposed_assets"]==1

def test_changed_vulnerable_count():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com", updated_at=datetime.now(timezone.utc))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert get_project_security_intelligence_summary(db,pid)["changed_vulnerable_assets"]==1

def test_highest_contextual_priority():
    db=_session()
    pid=str(uuid.uuid4())
    # Create low and critical
    ip_pub=_mk_asset(db,pid,"ip","8.8.8.8")
    dom=_mk_asset(db,pid,"domain","example.com", updated_at=datetime.now(timezone.utc)-timedelta(days=30), created_at=datetime.now(timezone.utc)-timedelta(days=30), last_seen_at=datetime.now(timezone.utc)-timedelta(days=30))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip_pub.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=dom.id, scanner="nuclei", title="t", severity="low", score=25))
    db.commit()
    assert get_project_security_intelligence_summary(db,pid)["highest_contextual_priority"]=="critical"
    # Informational case: no vuln
    db2=_session()
    pid2=str(uuid.uuid4())
    _mk_asset(db2,pid2,"domain","example.com", updated_at=datetime.now(timezone.utc)-timedelta(days=30), created_at=datetime.now(timezone.utc)-timedelta(days=30), last_seen_at=datetime.now(timezone.utc)-timedelta(days=30))
    assert get_project_security_intelligence_summary(db2,pid2)["highest_contextual_priority"]=="informational"

def test_attack_path_count():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    s=get_project_security_intelligence_summary(db,pid)
    assert s["attack_path_count"]==1
    assert s["attack_paths_truncated"] is False

def test_attack_path_truncation():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    for i in range(3):
        ip=_mk_asset(db,pid,"ip",f"8.8.8.{i+1}")
        _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    # Default max 100, not truncated
    assert get_project_security_intelligence_summary(db,pid, max_paths=10)["attack_paths_truncated"] is False
    # Force truncation
    assert get_project_security_intelligence_summary(db,pid, max_paths=1)["attack_paths_truncated"] is True
    assert get_project_security_intelligence_summary(db,pid, max_paths=1)["attack_path_count"]==1

def test_project_isolation():
    db=_session()
    pid_a=str(uuid.uuid4())
    pid_b=str(uuid.uuid4())
    dom_a=_mk_asset(db,pid_a,"domain","example.com")
    ip_a=_mk_asset(db,pid_a,"ip","8.8.8.8")
    _mk_rel(db,pid_a,dom_a.id,ip_a.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip_a.id, scanner="nuclei", title="t", severity="critical", score=90))
    dom_b=_mk_asset(db,pid_b,"domain","example.com")
    _mk_asset(db,pid_b,"ip","8.8.8.8")
    db.commit()
    s_a=get_project_security_intelligence_summary(db,pid_a)
    s_b=get_project_security_intelligence_summary(db,pid_b)
    assert s_a["critical_assets"]==1
    assert s_a["attack_path_count"]==1
    assert s_b["critical_assets"]==0
    assert s_b["attack_path_count"]==0

def test_deterministic_repeated():
    db=_session()
    pid=str(uuid.uuid4())
    _mk_asset(db,pid,"ip","8.8.8.8")
    s1=get_project_security_intelligence_summary(db,pid)
    s2=get_project_security_intelligence_summary(db,pid)
    assert s1==s2

def test_api_response():
    from app.schemas.asset import ProjectSecurityIntelligenceSummary
    data={"total_assets":1,"internet_facing_assets":1,"attack_path_count":1}
    obj=ProjectSecurityIntelligenceSummary.model_validate(data)
    assert obj.total_assets==1
    assert obj.internet_facing_assets==1

def test_existing_summary_compatibility():
    from app.schemas.asset import ProjectSecuritySummary
    # Old summary fields should still validate
    data={"total_assets":2,"internet_facing_assets":1,"web_applications":1,"exposed_services":1,"vulnerable_assets":1,"critical_assets":1,"sensitive_assets":0,"recently_changed_assets":1,"stale_assets":0,"inactive_assets":0}
    obj=ProjectSecuritySummary.model_validate(data)
    assert obj.total_assets==2
    # New summary should also accept old alias fields
    from app.schemas.asset import ProjectSecurityIntelligenceSummary
    obj2=ProjectSecurityIntelligenceSummary.model_validate(data)
    assert obj2.total_assets==2

def test_count_semantics():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    for _ in range(2):
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    s=get_project_security_intelligence_summary(db,pid)
    assert s["critical_assets"]==1
    assert s["high_assets"]==1
    assert s["vulnerable_assets"]==1

def test_no_n_plus_one():
    db=_session()
    pid=str(uuid.uuid4())
    for i in range(20):
        _mk_asset(db,pid,"domain",f"host{i}.example.com")
    import time
    start=time.time()
    s=get_project_security_intelligence_summary(db,pid)
    elapsed=time.time()-start
    assert s["total_assets"]==20
    assert elapsed < 2.0
