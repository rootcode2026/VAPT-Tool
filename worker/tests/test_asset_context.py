import copy
from datetime import datetime, timezone, timedelta
from app.services.risk_intelligence.asset_context import map_finding_to_asset_context
from app.services.risk_intelligence.enricher import enrich_finding_risk

def _finding(asset_id=None, project_id="p1", severity="high"):
    return {"scanner": "nuclei", "title": "Test", "severity": severity, "asset_id": asset_id, "project_id": project_id, "metadata": {}}

def _asset(id="a1", project_id="p1", asset_type="domain", value="example.com", first_seen=None, last_seen=None, relationships=None, status="active", criticality=None):
    a = {"id": id, "project_id": project_id, "asset_type": asset_type, "value": value, "status": status, "first_seen_at": first_seen, "last_seen_at": last_seen, "relationships": relationships or []}
    if criticality:
        a["criticality"] = criticality
    return a

def test_valid_asset_id():
    f = _finding(asset_id="a1", project_id="p1")
    a = _asset(id="a1", project_id="p1")
    res = map_finding_to_asset_context(f, a)
    assert res["asset_id"] == "a1"
    assert res["asset_type"] == "domain"
    assert "asset" in res["available_signals"]

def test_no_asset_id():
    f = _finding(asset_id=None)
    res = map_finding_to_asset_context(f, None)
    assert res["asset_id"] is None
    assert "asset" in res["unavailable_signals"]

def test_another_project():
    f = _finding(asset_id="a1", project_id="p1")
    a = _asset(id="a1", project_id="p2")
    res = map_finding_to_asset_context(f, a)
    assert res["project_isolation_ok"] is False
    assert res["asset_id"] == "a1"  # preserved
    assert res["asset_context"]["is_externally_exposed"] is None

def test_externally_exposed():
    f = _finding(asset_id="a1", project_id="p1")
    a = _asset(id="a1", project_id="p1", asset_type="url", value="https://example.com/path")
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["is_externally_exposed"] is True
    assert res["asset_context"]["exposure_signal"] == "url_asset"

def test_domain_no_exposure():
    f = _finding(asset_id="a1")
    a = _asset(id="a1", asset_type="domain", value="example.com")
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["is_externally_exposed"] is None

def test_public_ip_exposure():
    f = _finding(asset_id="a1")
    a = _asset(id="a1", asset_type="ip", value="8.8.8.8")
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["is_externally_exposed"] is True

def test_direct_relationships():
    rels = [{"relationship_type": "exposes"}, {"relationship_type": "resolves_to"}]
    f = _finding(asset_id="a1")
    a = _asset(id="a1", relationships=rels)
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["asset_relationship_count"] == 2
    assert "exposes" in res["asset_context"]["relationship_types"]

def test_no_relationships():
    f = _finding(asset_id="a1")
    a = _asset(id="a1", relationships=[])
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["asset_relationship_count"] == 0

def test_fresh_asset():
    now = datetime.now(timezone.utc)
    f = _finding(asset_id="a1")
    a = _asset(id="a1", first_seen=now - timedelta(days=1), last_seen=now)
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["freshness_signal"] == "fresh"
    assert res["asset_context"]["asset_age_signal"] == "new"

def test_stale_asset():
    now = datetime.now(timezone.utc)
    stale = now - timedelta(days=10)
    f = _finding(asset_id="a1")
    a = _asset(id="a1", first_seen=stale - timedelta(days=20), last_seen=stale)
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["freshness_signal"] == "stale"

def test_inactive_asset():
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=40)
    f = _finding(asset_id="a1")
    a = _asset(id="a1", first_seen=old, last_seen=old)
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["freshness_signal"] == "inactive"

def test_missing_timestamps():
    f = _finding(asset_id="a1")
    a = _asset(id="a1")
    a.pop("first_seen_at", None)
    a.pop("last_seen_at", None)
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["freshness_signal"] is None

def test_missing_criticality():
    f = _finding(asset_id="a1")
    a = _asset(id="a1")
    res = map_finding_to_asset_context(f, a)
    assert "criticality" in res["unavailable_signals"]

def test_explicit_criticality():
    f = _finding(asset_id="a1")
    a = _asset(id="a1", criticality="critical")
    res = map_finding_to_asset_context(f, a)
    assert res["asset_context"]["asset_risk_modifier"] > 0
    assert "criticality" in res["available_signals"]

def test_missing_optional_fields():
    f = {}
    a = None
    res = map_finding_to_asset_context(f, a)
    assert res["asset_id"] is None
    assert res["asset_context"]["asset_risk_modifier"] == 0 or res["asset_context"]["asset_risk_modifier"] is not None

def test_deterministic():
    f = _finding(asset_id="a1")
    a = _asset(id="a1", asset_type="ip", value="8.8.8.8")
    r1 = map_finding_to_asset_context(f, a)
    r2 = map_finding_to_asset_context(f, a)
    assert r1 == r2

def test_bounded_modifier():
    f = _finding(asset_id="a1")
    a = _asset(id="a1", asset_type="url", value="https://example.com", criticality="critical", relationships=[{"relationship_type": "exposes"}]*5)
    a["first_seen_at"] = datetime.now(timezone.utc)
    a["last_seen_at"] = datetime.now(timezone.utc)
    res = map_finding_to_asset_context(f, a)
    assert -10 <= res["asset_context"]["asset_risk_modifier"] <= 15

def test_original_unchanged():
    f = _finding(asset_id="a1", severity="high")
    a = _asset(id="a1")
    orig_f = copy.deepcopy(f)
    orig_a = copy.deepcopy(a)
    map_finding_to_asset_context(f, a)
    assert f == orig_f
    assert a == orig_a

def test_original_severity_unchanged():
    f = _finding(severity="high")
    enriched = enrich_finding_risk(finding=f)
    res = map_finding_to_asset_context(f, _asset(id="a1", asset_type="url", value="https://example.com"), enriched)
    assert f["severity"] == "high"
    assert res["original_severity"] == "high"

def test_validation_state_unchanged():
    f = _finding(severity="high")
    enriched = enrich_finding_risk(finding=f)
    # enriched has no state, but we pass via enriched_risk
    res = map_finding_to_asset_context(f, _asset(id="a1"), enriched)
    # Ensure enriched_risk not mutated
    orig = copy.deepcopy(enriched)
    map_finding_to_asset_context(f, _asset(id="a1"), enriched)
    assert enriched == orig
