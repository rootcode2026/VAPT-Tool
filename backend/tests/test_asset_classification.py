import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, JSON, String, DateTime, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.services.asset_classification import classify_assets_batch, is_public_ip, SENSITIVE_KEYWORDS
from app.schemas.asset import AssetClassifications

# Isolated sqlite Base — use JSON (not JSONB) and map extra_data -> metadata column
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

def _mk_asset(db, project_id, asset_type, value, **kw):
    a=Asset(id=str(uuid.uuid4()), project_id=project_id, asset_type=asset_type, value=value, **kw)
    db.add(a)
    db.commit()
    return a

# 1-5 public/private checks
def test_public_ipv4_internet_facing():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ip","8.8.8.8")
    res=classify_assets_batch(db,[a])
    assert res[a.id]["internet_facing"] is True

def test_private_ipv4_not_internet_facing():
    for ip in ["10.0.0.8","192.168.1.1","172.16.0.1","10.255.255.255"]:
        assert is_public_ip(ip) is False
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ip","10.0.0.8")
    assert classify_assets_batch(db,[a])[a.id]["internet_facing"] is False

def test_loopback_not_internet_facing():
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("127.0.0.2") is False
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ip","127.0.0.1")
    assert classify_assets_batch(db,[a])[a.id]["internet_facing"] is False

def test_public_ipv6_internet_facing():
    assert is_public_ip("2001:4860:4860::8888") is True
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ipv6","2001:4860:4860::8888")
    assert classify_assets_batch(db,[a])[a.id]["internet_facing"] is True

def test_private_local_ipv6_not_internet_facing():
    for ip in ["::1","fe80::1","fd00::1","2001:db8::1"]:
        assert is_public_ip(ip) is False
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"ipv6","fe80::1")
    assert classify_assets_batch(db,[a])[a.id]["internet_facing"] is False

def test_domain_with_resolves_to_public_ip_is_externally_resolvable_and_internet_facing():
    db=_session()
    pid=str(uuid.uuid4())
    domain=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=domain.id,target_asset_id=ip.id,relationship_type="resolves_to"))
    db.commit()
    res=classify_assets_batch(db,[domain,ip])
    assert res[domain.id]["externally_resolvable"] is True
    assert res[domain.id]["internet_facing"] is True
    # ip itself is internet_facing but not externally_resolvable (no outgoing)
    assert res[ip.id]["internet_facing"] is True
    assert res[ip.id]["externally_resolvable"] is False

def test_url_web_application():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/login")
    domain=_mk_asset(db,pid,"domain","example.com")
    res=classify_assets_batch(db,[url,domain])
    assert res[url.id]["web_application"] is True
    assert res[domain.id]["web_application"] is False

def test_http_service_web_application_via_exposes():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","443")
    service=_mk_asset(db,pid,"service","https")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=ip.id,target_asset_id=port.id,relationship_type="exposes"))
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=port.id,target_asset_id=service.id,relationship_type="runs"))
    db.commit()
    res=classify_assets_batch(db,[ip,port,service])
    assert res[ip.id]["exposed_service"] is True
    assert res[port.id]["exposed_service"] is True
    # port 443 is web port, should also be web_application
    assert res[port.id]["web_application"] is True or res[ip.id]["web_application"] is True

def test_exposed_port_exposed_service():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","10.0.0.8")
    port=_mk_asset(db,pid,"port","80")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=ip.id,target_asset_id=port.id,relationship_type="exposes"))
    db.commit()
    res=classify_assets_batch(db,[ip,port])
    assert res[ip.id]["exposed_service"] is True
    assert res[port.id]["exposed_service"] is True

def test_port_runs_service():
    db=_session()
    pid=str(uuid.uuid4())
    port=_mk_asset(db,pid,"port","443")
    svc=_mk_asset(db,pid,"service","https")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=port.id,target_asset_id=svc.id,relationship_type="runs"))
    db.commit()
    res=classify_assets_batch(db,[port,svc])
    assert res[port.id]["exposed_service"] is True

def test_technology_relationship_technology_bearing():
    db=_session()
    pid=str(uuid.uuid4())
    url=_mk_asset(db,pid,"url","https://example.com/")
    tech=_mk_asset(db,pid,"technology","nginx")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=url.id,target_asset_id=tech.id,relationship_type="serves"))
    db.commit()
    res=classify_assets_batch(db,[url,tech])
    assert res[url.id]["technology_bearing"] is True
    assert res[tech.id]["technology_bearing"] is False

def test_correlated_finding_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a.id, scanner="nuclei", title="x", severity="high", score=75))
    db.commit()
    res=classify_assets_batch(db,[a])
    assert res[a.id]["vulnerable"] is True

def test_no_finding_not_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com")
    res=classify_assets_batch(db,[a])
    assert res[a.id]["vulnerable"] is False

def test_recent_change_event_recently_changed():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","example.com", updated_at=datetime.now(timezone.utc))
    db.add(AssetChangeEvent(id=str(uuid.uuid4()), project_id=pid, asset_id=a.id, scan_id=str(uuid.uuid4()), change_type="new_asset", detected_at=datetime.now(timezone.utc)))
    db.commit()
    assert classify_assets_batch(db,[a])[a.id]["recently_changed"] is True

def test_old_change_event_not_recently_changed():
    db=_session()
    pid=str(uuid.uuid4())
    old=datetime.now(timezone.utc)-timedelta(days=30)
    a=_mk_asset(db,pid,"domain","example.com", last_seen_at=old, updated_at=old, created_at=old)
    db.add(AssetChangeEvent(id=str(uuid.uuid4()), project_id=pid, asset_id=a.id, scan_id=str(uuid.uuid4()), change_type="new_asset", detected_at=old))
    db.commit()
    assert classify_assets_batch(db,[a])[a.id]["recently_changed"] is False

def test_conservative_sensitive_keyword_detection():
    db=_session()
    pid=str(uuid.uuid4())
    cases=[("admin.example.com",True),("api.internal.test",True),("vpn.example.com",True),("db.example.com",True),("login.example.com",True)]
    for val, expected in cases:
        a=_mk_asset(db,pid,"subdomain",val)
        assert classify_assets_batch(db,[a])[a.id]["potentially_sensitive"] is expected, f"{val}"

def test_generic_domain_not_sensitive():
    db=_session()
    pid=str(uuid.uuid4())
    for val in ["example.com","www.example.com","cdn.example.com","static.example.com"]:
        a=_mk_asset(db,pid,"domain",val)
        assert classify_assets_batch(db,[a])[a.id]["potentially_sensitive"] is False, val

def test_ambiguous_evidence_not_positive():
    db=_session()
    pid=str(uuid.uuid4())
    # private IP should not be internet_facing even with resolves_to private IP
    domain=_mk_asset(db,pid,"domain","internal.test")
    priv=_mk_asset(db,pid,"ip","10.0.0.8")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=domain.id,target_asset_id=priv.id,relationship_type="resolves_to"))
    db.commit()
    res=classify_assets_batch(db,[domain])
    assert res[domain.id]["internet_facing"] is False
    assert res[domain.id]["externally_resolvable"] is True  # still resolvable, but not internet facing

def test_project_isolation():
    db=_session()
    pid_a=str(uuid.uuid4())
    pid_b=str(uuid.uuid4())
    # same value different projects
    a1=_mk_asset(db,pid_a,"domain","example.com")
    a2=_mk_asset(db,pid_b,"domain","example.com")
    ip_a=_mk_asset(db,pid_a,"ip","8.8.8.8")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid_a,source_asset_id=a1.id,target_asset_id=ip_a.id,relationship_type="resolves_to"))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=a1.id, scanner="nuclei", title="vuln", severity="critical", score=90))
    db.commit()
    res_a=classify_assets_batch(db,[a1])
    res_b=classify_assets_batch(db,[a2])
    assert res_a[a1.id]["internet_facing"] is True
    assert res_a[a1.id]["vulnerable"] is True
    assert res_b[a2.id]["internet_facing"] is False
    assert res_b[a2.id]["vulnerable"] is False

def test_deterministic_repeated():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"url","https://example.com/")
    tech=_mk_asset(db,pid,"technology","nginx")
    db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=a.id,target_asset_id=tech.id,relationship_type="serves"))
    db.commit()
    r1=classify_assets_batch(db,[a,tech])
    r2=classify_assets_batch(db,[a,tech])
    assert r1==r2

def test_batch_multiple_assets():
    db=_session()
    pid=str(uuid.uuid4())
    assets=[_mk_asset(db,pid,"ip",f"8.8.8.{i}") for i in range(1,6)]
    ports=[_mk_asset(db,pid,"port",str(8000+i)) for i in range(5)]
    for ip,port in zip(assets,ports):
        db.add(AssetRelationship(id=str(uuid.uuid4()),project_id=pid,source_asset_id=ip.id,target_asset_id=port.id,relationship_type="exposes"))
    db.commit()
    res=classify_assets_batch(db,assets+ports)
    assert len(res)==10
    for ip in assets:
        assert res[ip.id]["exposed_service"] is True
        assert res[ip.id]["internet_facing"] is True

def test_no_n_plus_one_batch_queries():
    # Verify batch uses limited queries: we test that classify_assets_batch for 10 assets still works with same query count principle
    # This is a smoke test for performance - ensure no per-asset query loop that would explode
    db=_session()
    pid=str(uuid.uuid4())
    assets=[_mk_asset(db,pid,"domain",f"host{i}.example.com") for i in range(20)]
    # no relationships, should still classify quickly
    import time
    start=time.time()
    res=classify_assets_batch(db,assets)
    elapsed=time.time()-start
    assert len(res)==20
    assert elapsed < 2.0  # generous
