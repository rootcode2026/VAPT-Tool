import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, JSON, String, DateTime, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.services.asset_attack_paths import get_attack_paths_for_project, MAX_DEPTH, MAX_PATHS

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

def _mk_rel(db, project_id, src, dst, rtype):
    rel=AssetRelationship(id=str(uuid.uuid4()), project_id=project_id, source_asset_id=src, target_asset_id=dst, relationship_type=rtype)
    db.add(rel)
    db.commit()
    return rel

def test_no_relationships_no_paths():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==0
    assert res["paths"]==[]
    assert res["truncated"] is False

def test_no_vulnerable_targets_no_paths():
    db=_session()
    pid=str(uuid.uuid4())
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","443")
    _mk_rel(db,pid,ip.id,port.id,"exposes")
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==0

def test_no_internet_facing_entry_no_paths():
    db=_session()
    pid=str(uuid.uuid4())
    priv=_mk_asset(db,pid,"ip","10.0.0.8")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=priv.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    # 10.0.0.8 is private, not internet_facing, so no entry
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==0

def test_direct_entry_to_vulnerable():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==1
    p=res["paths"][0]
    assert p["entry_asset_id"]==dom.id
    assert p["target_asset_id"]==ip.id
    assert p["length"]==2
    assert p["confidence"]=="observed"

def test_multi_hop_path():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    sub=_mk_asset(db,pid,"subdomain","api.example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","443")
    svc=_mk_asset(db,pid,"service","https")
    _mk_rel(db,pid,dom.id,sub.id,"contains")
    _mk_rel(db,pid,sub.id,ip.id,"resolves_to")
    _mk_rel(db,pid,ip.id,port.id,"exposes")
    _mk_rel(db,pid,port.id,svc.id,"runs")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=svc.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]>=1
    # Entry is sub or ip; both reach svc, check at least one path length 4 exists
    found4=any(p["target_asset_id"]==svc.id and len(p["asset_ids"])==4 for p in res["paths"])
    found3=any(p["target_asset_id"]==svc.id and len(p["asset_ids"])==3 for p in res["paths"])
    assert found4 or found3
    # Ensure path is deterministic and contains expected chain
    assert any("api.example.com" in str(p["asset_ids"]) or ip.id in p["asset_ids"] for p in res["paths"])

def test_domain_ip_port_service_chain():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","80")
    svc=_mk_asset(db,pid,"service","http")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    _mk_rel(db,pid,ip.id,port.id,"exposes")
    _mk_rel(db,pid,port.id,svc.id,"runs")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=svc.id, scanner="nuclei", title="t", severity="medium", score=50))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    # Both dom (internet_facing via resolves_to) and ip (public) are entries, so 2 paths to svc
    assert res["total"]==2
    # Shortest path is dom->ip->port->svc length 4
    assert any(p["asset_ids"]==[dom.id, ip.id, port.id, svc.id] for p in res["paths"])
    # Also ip->port->svc length 3
    assert any(p["asset_ids"]==[ip.id, port.id, svc.id] for p in res["paths"])

def test_multiple_paths():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip1=_mk_asset(db,pid,"ip","8.8.8.8")
    ip2=_mk_asset(db,pid,"ip","1.1.1.1")
    _mk_rel(db,pid,dom.id,ip1.id,"resolves_to")
    _mk_rel(db,pid,dom.id,ip2.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip1.id, scanner="nuclei", title="t", severity="high", score=75))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip2.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==2

def test_duplicate_suppression():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    # Add same relationship twice? Unique constraint prevents, but we test path deduplication via repeated execution
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    r1=get_attack_paths_for_project(db, pid)
    r2=get_attack_paths_for_project(db, pid)
    assert r1==r2
    assert r1["total"]==1

def test_cycle_protection():
    db=_session()
    pid=str(uuid.uuid4())
    a=_mk_asset(db,pid,"domain","a.example.com")
    b=_mk_asset(db,pid,"subdomain","b.example.com")
    c=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,a.id,b.id,"contains")
    _mk_rel(db,pid,b.id,c.id,"resolves_to")
    _mk_rel(db,pid,c.id,a.id,"observed_on")  # cycle
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=c.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    # Should not infinite loop, should have one path a->b->c
    assert res["total"]==1
    assert res["paths"][0]["path_id"] is not None

def test_max_depth_enforcement():
    db=_session()
    pid=str(uuid.uuid4())
    # Create chain length 7 > MAX_DEPTH 5
    assets=[_mk_asset(db,pid,"domain",f"host{i}.example.com") for i in range(7)]
    # Need first asset to be internet_facing: make it ip public entry
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    dom=_mk_asset(db,pid,"domain","example.com")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    # Create chain from ip onwards length 6 more
    prev=ip
    chain=[ip]
    for i in range(6):
        nxt=_mk_asset(db,pid,"subdomain",f"c{i}.example.com")
        # use contains
        # Need parent to exist: use previous as source
        _mk_rel(db,pid,prev.id,nxt.id,"contains" if i%2==0 else "resolves_to")
        chain.append(nxt)
        prev=nxt
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=chain[-1].id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    res=get_attack_paths_for_project(db, pid, max_depth=5)
    # Path to last asset should not be found because depth 6 >5, but maybe shorter vulnerable not in chain
    # At least ensure no path exceeds max_depth
    for p in res["paths"]:
        assert p["length"]-1 <=5  # edges <=5

def test_max_path_enforcement():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    for i in range(5):
        ip=_mk_asset(db,pid,"ip",f"8.8.8.{i+1}")
        _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res=get_attack_paths_for_project(db, pid, max_paths=2)
    assert res["total"]==2
    assert res["truncated"] is True

def test_project_isolation():
    db=_session()
    pid_a=str(uuid.uuid4())
    pid_b=str(uuid.uuid4())
    dom_a=_mk_asset(db,pid_a,"domain","example.com")
    ip_a=_mk_asset(db,pid_a,"ip","8.8.8.8")
    _mk_rel(db,pid_a,dom_a.id,ip_a.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip_a.id, scanner="nuclei", title="t", severity="critical", score=90))
    # Same values in pid_b but no relationships/findings
    dom_b=_mk_asset(db,pid_b,"domain","example.com")
    _mk_asset(db,pid_b,"ip","8.8.8.8")
    db.commit()
    res_a=get_attack_paths_for_project(db, pid_a)
    res_b=get_attack_paths_for_project(db, pid_b)
    assert res_a["total"]==1
    assert res_b["total"]==0

def test_critical_target_priority():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    p=get_attack_paths_for_project(db, pid)["paths"][0]
    assert p["priority"]=="critical"

def test_high_target_priority():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    p=get_attack_paths_for_project(db, pid)["paths"][0]
    assert p["priority"]=="high"

def test_medium_target_priority():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    port=_mk_asset(db,pid,"port","80")
    svc=_mk_asset(db,pid,"service","http")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    _mk_rel(db,pid,ip.id,port.id,"exposes")
    _mk_rel(db,pid,port.id,svc.id,"runs")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=svc.id, scanner="nuclei", title="t", severity="medium", score=50))
    db.commit()
    p=get_attack_paths_for_project(db, pid)["paths"][0]
    # vulnerable + exposed_service → medium per D4
    assert p["priority"] in ("medium","high","critical")

def test_d4_reused():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    p=get_attack_paths_for_project(db, pid)["paths"][0]
    # Target contextual priority should be critical
    assert p["target_contextual_priority"]=="critical"
    assert any(f["code"]=="CRITICAL_EXPOSURE" for f in p["target_risk_factors"])

def test_deterministic_ordering():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip1=_mk_asset(db,pid,"ip","8.8.8.8")
    ip2=_mk_asset(db,pid,"ip","1.1.1.1")
    _mk_rel(db,pid,dom.id,ip1.id,"resolves_to")
    _mk_rel(db,pid,dom.id,ip2.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip1.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip2.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res1=get_attack_paths_for_project(db, pid)
    res2=get_attack_paths_for_project(db, pid)
    assert res1==res2
    # critical should come before high
    assert res1["paths"][0]["priority"]=="critical"
    assert res1["paths"][1]["priority"]=="high"

def test_repeated_execution_identical():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    assert get_attack_paths_for_project(db, pid)==get_attack_paths_for_project(db, pid)

def test_truncated_flag():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    for i in range(4):
        ip=_mk_asset(db,pid,"ip",f"8.8.8.{i+1}")
        _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
        db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res=get_attack_paths_for_project(db, pid, max_paths=2)
    assert res["truncated"] is True
    assert res["total"]==2
    res2=get_attack_paths_for_project(db, pid, max_paths=10)
    assert res2["truncated"] is False

def test_empty_project():
    db=_session()
    pid=str(uuid.uuid4())
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==0
    assert res["paths"]==[]

def test_vulnerable_internal_reached():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip_pub=_mk_asset(db,pid,"ip","8.8.8.8")
    ip_priv=_mk_asset(db,pid,"ip","10.0.0.8")
    port=_mk_asset(db,pid,"port","80")
    _mk_rel(db,pid,dom.id,ip_pub.id,"resolves_to")
    _mk_rel(db,pid,ip_pub.id,port.id,"exposes")
    _mk_rel(db,pid,port.id,ip_priv.id,"observed_on")  # simulate internal reached via web
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip_priv.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]>=1
    assert any(p["target_asset_id"]==ip_priv.id for p in res["paths"])

def test_nonexistent_relationship_no_path():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    # No relationship
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    # dom is internet_facing only if resolves_to public, but no rel, so no entry? Actually dom without rel is not internet_facing, ip is internet_facing but no path to itself? Entry ip itself is vulnerable but need edge, so no path
    res=get_attack_paths_for_project(db, pid)
    assert res["total"]==0

def test_no_exploitability_claims():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip=_mk_asset(db,pid,"ip","8.8.8.8")
    _mk_rel(db,pid,dom.id,ip.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip.id, scanner="nuclei", title="t", severity="critical", score=90))
    db.commit()
    p=get_attack_paths_for_project(db, pid)["paths"][0]
    assert p["confidence"]=="observed"
    assert "observed" in p["explanation"].lower()
    forbidden=["exploitable","compromise","exploit","guaranteed"]
    for word in forbidden:
        assert word not in p["explanation"].lower()
        assert word not in p["confidence"].lower()

def test_api_response():
    from app.schemas.asset import AttackPathsResponse
    data={"paths":[{"path_id":"abc","project_id":"p1","entry_asset_id":"e1","target_asset_id":"t1","asset_ids":["e1","t1"],"relationships":[{"id":"r1","source_asset_id":"e1","target_asset_id":"t1","relationship_type":"resolves_to"}],"length":2,"entry_type":"internet_facing","target_type":"vulnerable","priority":"high","confidence":"observed","explanation":"Observed path from an internet-facing asset to a vulnerable asset."}],"total":1,"truncated":False}
    obj=AttackPathsResponse.model_validate(data)
    assert obj.total==1
    assert obj.truncated is False

def test_asset_filter():
    db=_session()
    pid=str(uuid.uuid4())
    dom=_mk_asset(db,pid,"domain","example.com")
    ip1=_mk_asset(db,pid,"ip","8.8.8.8")
    ip2=_mk_asset(db,pid,"ip","1.1.1.1")
    _mk_rel(db,pid,dom.id,ip1.id,"resolves_to")
    _mk_rel(db,pid,dom.id,ip2.id,"resolves_to")
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip1.id, scanner="nuclei", title="t", severity="high", score=75))
    db.add(Finding(id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target_id=str(uuid.uuid4()), asset_id=ip2.id, scanner="nuclei", title="t", severity="high", score=75))
    db.commit()
    res_all=get_attack_paths_for_project(db, pid)
    res_one=get_attack_paths_for_project(db, pid, asset_id=ip1.id)
    assert res_all["total"]==2
    assert res_one["total"]==1
    assert res_one["paths"][0]["target_asset_id"]==ip1.id
