from app.services.risk_intelligence.enricher import enrich_finding_risk, enrich_findings_risk
import copy

def _finding(severity="high", score=75):
    return {"scanner": "nuclei", "title": "Test", "severity": severity, "score": score, "status": "open"}

def _validation(scanner_count=1, confidence_score=40, has_asset=False, has_cve=False):
    return {
        "scanner_count": scanner_count,
        "scanners": ["nuclei"] if scanner_count==1 else ["nuclei","zap"][:scanner_count],
        "confidence_score": confidence_score,
        "confidence_level": "medium" if confidence_score>=40 else "low",
        "signals": {"scanner_count": scanner_count, "has_asset": has_asset, "has_cve": has_cve},
        "evidence_count": 1,
        "state": "detected" if scanner_count==1 else "corroborated",
    }

def _provenance(quality=50, evidence_count=1):
    return {"provenance_quality_score": quality, "evidence_count": evidence_count, "coverage": {"has_asset": False, "has_url": True}, "independent_scanner_count": 1}

# 1
def test_critical_high_medium():
    for sev in ["critical","high","medium","low","info"]:
        res = enrich_finding_risk(finding=_finding(severity=sev))
        assert res["severity"] == sev
        assert 0 <= res["risk_score"] <= 100

# 2
def test_high_confidence_vs_low():
    low = enrich_finding_risk(finding=_finding(), validation=_validation(confidence_score=20))
    high = enrich_finding_risk(finding=_finding(), validation=_validation(confidence_score=90))
    assert high["risk_score"] > low["risk_score"]

# 3
def test_single_vs_corroborated():
    single = enrich_finding_risk(finding=_finding(), validation=_validation(scanner_count=1))
    corr = enrich_finding_risk(finding=_finding(), validation=_validation(scanner_count=2))
    assert corr["risk_score"] > single["risk_score"]

# 4
def test_evidence_quality():
    low = enrich_finding_risk(finding=_finding(), provenance=_provenance(quality=10))
    high = enrich_finding_risk(finding=_finding(), provenance=_provenance(quality=90))
    assert high["risk_score"] >= low["risk_score"]

# 5
def test_cve_presence():
    with_cve = enrich_finding_risk(finding=_finding(), normalized={"severity":"high","cve":"CVE-2021-0001"})
    without = enrich_finding_risk(finding=_finding(), normalized={"severity":"high"})
    assert with_cve["risk_score"] >= without["risk_score"]

# 6
def test_missing_fields():
    res = enrich_finding_risk(finding={})
    assert 0 <= res["risk_score"] <= 100
    assert "severity" in res

# 7
def test_score_bounded():
    for sev in ["critical","high","medium","low","info"]:
        res = enrich_finding_risk(finding=_finding(severity=sev))
        assert 0 <= res["risk_score"] <= 100

# 8
def test_deterministic():
    f = _finding(severity="high")
    v = _validation(scanner_count=2, confidence_score=70)
    p = _provenance(quality=70)
    r1 = enrich_finding_risk(finding=f, validation=v, provenance=p)
    r2 = enrich_finding_risk(finding=f, validation=v, provenance=p)
    assert r1 == r2

# 9
def test_original_severity_unchanged():
    f = _finding(severity="high")
    res = enrich_finding_risk(finding=f)
    assert res["original_severity"] == "high"
    assert res["severity"] == "high"

# 10
def test_validation_state_unchanged():
    val = _validation(scanner_count=1)
    val["state"] = "detected"
    res = enrich_finding_risk(finding=_finding(), validation=val)
    assert val["state"] == "detected"
    assert res["confidence_score"] == val["confidence_score"]

# 11
def test_no_fabricated_unavailable():
    res = enrich_finding_risk(finding=_finding())
    assert "exploitability" in res["unavailable_signals"]
    assert "business_criticality" in res["unavailable_signals"]
    assert "exploitability" not in res["available_signals"]

# 12
def test_multiple_findings():
    findings = [{"finding": _finding(severity="high"), "validation": _validation(scanner_count=1)}, {"finding": _finding(severity="critical"), "validation": _validation(scanner_count=2)}]
    res = enrich_findings_risk(findings)
    assert len(res) == 2
    # Deterministic sorted by risk_score
    assert res[0]["risk_score"] <= res[1]["risk_score"]
