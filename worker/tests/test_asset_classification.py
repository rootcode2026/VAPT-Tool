from datetime import datetime, timedelta, timezone
from app.asset_intel.classification import classify_assets_maps, is_public_ip, is_sensitive_value

def _asset(id, atype, value, project_id="p1", **kw):
    return {"id": id, "asset_type": atype, "value": value, "project_id": project_id, **kw}

def _rel(sid, tid, rtype, pid="p1"):
    return {"source_asset_id": sid, "target_asset_id": tid, "relationship_type": rtype, "project_id": pid}

def test_public_ipv4():
    assert is_public_ip("8.8.8.8")
    assets=[_asset("a1","ip","8.8.8.8")]
    res=classify_assets_maps(assets, [], {}, {})
    assert res["a1"]["internet_facing"] is True

def test_private_ipv4():
    assert not is_public_ip("10.0.0.8")
    assets=[_asset("a1","ip","10.0.0.8")]
    assert classify_assets_maps(assets, [], {}, {})["a1"]["internet_facing"] is False

def test_loopback():
    assert not is_public_ip("127.0.0.1")
    assets=[_asset("a1","ip","127.0.0.1")]
    assert classify_assets_maps(assets, [], {}, {})["a1"]["internet_facing"] is False

def test_public_ipv6():
    assert is_public_ip("2001:4860:4860::8888")
    assets=[_asset("a1","ipv6","2001:4860:4860::8888")]
    assert classify_assets_maps(assets, [], {}, {})["a1"]["internet_facing"] is True

def test_private_ipv6():
    assert not is_public_ip("fe80::1")
    assert not is_public_ip("2001:db8::1")

def test_domain_resolves_to_public():
    assets=[_asset("d1","domain","example.com"),_asset("ip1","ip","8.8.8.8")]
    rels=[_rel("d1","ip1","resolves_to")]
    res=classify_assets_maps(assets, rels, {}, {})
    assert res["d1"]["externally_resolvable"] is True
    assert res["d1"]["internet_facing"] is True

def test_url_web_app():
    assets=[_asset("u1","url","https://example.com/"),_asset("d1","domain","example.com")]
    res=classify_assets_maps(assets, [], {}, {})
    assert res["u1"]["web_application"] is True
    assert res["d1"]["web_application"] is False

def test_exposed_port():
    assets=[_asset("ip1","ip","8.8.8.8"),_asset("p1","port","443")]
    rels=[_rel("ip1","p1","exposes")]
    res=classify_assets_maps(assets, rels, {}, {})
    assert res["ip1"]["exposed_service"] is True
    assert res["p1"]["exposed_service"] is True

def test_port_runs_service():
    assets=[_asset("p1","port","443"),_asset("s1","service","https")]
    rels=[_rel("p1","s1","runs")]
    assert classify_assets_maps(assets, rels, {}, {})["p1"]["exposed_service"] is True

def test_technology_bearing():
    assets=[_asset("u1","url","https://example.com/"),_asset("t1","technology","nginx")]
    rels=[_rel("u1","t1","serves")]
    assert classify_assets_maps(assets, rels, {}, {})["u1"]["technology_bearing"] is True
    assert classify_assets_maps(assets, rels, {}, {})["t1"]["technology_bearing"] is False

def test_vulnerable():
    assets=[_asset("a1","domain","example.com")]
    findings={"a1":[{"severity":"high"}]}
    assert classify_assets_maps(assets, [], findings, {})["a1"]["vulnerable"] is True
    assert classify_assets_maps(assets, [], {}, {})["a1"]["vulnerable"] is False

def test_recently_changed():
    now=datetime.now(timezone.utc)
    recent=now
    old=now-timedelta(days=30)
    assets=[_asset("a1","domain","example.com", last_seen_at=recent),_asset("a2","domain","old.com", last_seen_at=old)]
    assert classify_assets_maps(assets, [], {}, {})["a1"]["recently_changed"] is True
    assert classify_assets_maps(assets, [], {}, {})["a2"]["recently_changed"] is False
    # via change event
    assets2=[_asset("a3","domain","ev.com")]
    events={"a3":[{"detected_at":now}]}
    assert classify_assets_maps(assets2, [], {}, events)["a3"]["recently_changed"] is True
    events_old={"a3":[{"detected_at":old}]}
    assert classify_assets_maps(assets2, [], {}, events_old)["a3"]["recently_changed"] is False

def test_sensitive():
    assert is_sensitive_value("admin.example.com")
    assert is_sensitive_value("api.internal.test")
    assert not is_sensitive_value("example.com")
    assert not is_sensitive_value("www.example.com")
    assets=[_asset("a1","subdomain","admin.example.com"),_asset("a2","domain","example.com")]
    res=classify_assets_maps(assets, [], {}, {})
    assert res["a1"]["potentially_sensitive"] is True
    assert res["a2"]["potentially_sensitive"] is False

def test_generic_not_sensitive():
    assert not is_sensitive_value("www.example.com")
    assert not is_sensitive_value("cdn.example.com")

def test_ambiguous_not_positive():
    # private resolves should not make internet_facing true
    assets=[_asset("d1","domain","internal.test"),_asset("ip1","ip","10.0.0.8")]
    rels=[_rel("d1","ip1","resolves_to")]
    res=classify_assets_maps(assets, rels, {}, {})
    assert res["d1"]["internet_facing"] is False
    assert res["d1"]["externally_resolvable"] is True

def test_project_isolation_worker():
    assets=[_asset("a1","domain","example.com",project_id="p1"),_asset("a2","domain","example.com",project_id="p2"),_asset("ip1","ip","8.8.8.8",project_id="p1")]
    rels=[_rel("a1","ip1","resolves_to",pid="p1")]
    findings={"a1":[{}]}
    res=classify_assets_maps(assets, rels, findings, {})
    assert res["a1"]["internet_facing"] is True
    assert res["a1"]["vulnerable"] is True
    assert res["a2"]["internet_facing"] is False
    assert res["a2"]["vulnerable"] is False

def test_deterministic():
    assets=[_asset("u1","url","https://example.com/"),_asset("t1","technology","nginx")]
    rels=[_rel("u1","t1","serves")]
    r1=classify_assets_maps(assets, rels, {}, {})
    r2=classify_assets_maps(assets, rels, {}, {})
    assert r1==r2

def test_batch_multiple():
    assets=[_asset(f"ip{i}","ip",f"8.8.8.{i}") for i in range(1,6)]
    rels=[]
    for i in range(1,6):
        assets.append(_asset(f"p{i}","port",str(8000+i)))
        rels.append(_rel(f"ip{i}",f"p{i}","exposes"))
    res=classify_assets_maps(assets, rels, {}, {})
    assert len(res)==10
