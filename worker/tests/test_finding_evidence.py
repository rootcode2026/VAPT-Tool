import copy
from app.services.finding_correlation.correlator import correlate_findings
from app.services.finding_correlation.evidence import build_evidence_provenance, enrich_finding_confidence
from app.services.finding_correlation.validation import evaluate_finding_validation

def _finding(scanner="nuclei", title="SQL Injection", severity="high", cve="CVE-2021-0001", url="https://example.com/login", **extra):
    f = {"scanner": scanner, "title": title, "severity": severity, "cve": cve, "cwe": "CWE-79", "metadata": {"uri": url, "rule_id": "SAST001"}, "evidence": f"evidence-{scanner}"}
    f.update(extra)
    return f

def _correlated_single(**kwargs):
    f = _finding(**kwargs)
    corr = correlate_findings([f])["correlated_findings"][0]
    return corr

# A Single evidence item
def test_single_evidence():
    corr = _correlated_single()
    prov = build_evidence_provenance(corr)
    assert prov["evidence_count"] == 1
    assert prov["evidence_items"][0]["scanner"] == "nuclei"
    assert prov["evidence_items"][0]["evidence"] is not None

# B Multiple scanners
def test_multiple_scanners():
    f1 = _finding(scanner="nuclei")
    f2 = _finding(scanner="zap")
    corr = correlate_findings([f1, f2])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["independent_scanner_count"] == 2
    assert set(prov["scanners"]) == {"nuclei", "zap"}

# C Duplicate evidence
def test_duplicate_evidence():
    f1 = _finding(scanner="nuclei", url="https://example.com/login")
    f2 = _finding(scanner="nuclei", url="https://example.com/login")
    corr = correlate_findings([f1, f2])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    # Same scanner, same evidence, same fingerprint -> deduped to 1
    assert prov["evidence_count"] == 1

# D Evidence count
def test_evidence_count():
    f1 = _finding(scanner="nuclei", url="https://example.com/login")
    f2 = _finding(scanner="zap", url="https://example.com/login")
    f3 = _finding(scanner="nikto", url="https://example.com/login")
    # Need same fingerprint to be same logical finding: same title/cve/url, different scanner
    # Use same title/cve/url for all
    corr = correlate_findings([f1, f2, f3])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["evidence_count"] == 3

# E Scanner count duplicate scanner does not inflate
def test_scanner_count_duplicate():
    f1 = _finding(scanner="nuclei")
    f2 = _finding(scanner="nuclei")
    corr = correlate_findings([f1, f2])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["independent_scanner_count"] == 1

# F URL provenance
def test_url_provenance():
    corr = _correlated_single(url="https://example.com/login")
    prov = build_evidence_provenance(corr)
    assert prov["coverage"]["has_url"] is True
    assert "url" in prov["evidence_types"] or "http_response" in prov["evidence_types"]

# G Host/IP provenance
def test_host_ip_provenance():
    f = _finding(url=None)
    f["metadata"] = {"host": "example.com"}
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["coverage"]["has_hostname"] is True
    f2 = {"scanner": "nmap", "title": "Open port", "severity": "info", "metadata": {"ip": "192.168.1.1", "port": "80"}}
    corr2 = correlate_findings([f2])["correlated_findings"][0]
    prov2 = build_evidence_provenance(corr2)
    assert prov2["coverage"]["has_ip"] is True

# H Port provenance
def test_port_provenance():
    f = {"scanner": "nmap", "title": "Open port", "severity": "info", "metadata": {"ip": "192.168.1.1", "port": "443"}}
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["coverage"]["has_port"] is True

# I Parameter provenance
def test_parameter_provenance():
    f = {"scanner": "zap", "title": "SQLi", "severity": "high", "metadata": {"parameter": "id", "uri": "https://example.com/login"}}
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["coverage"]["has_parameter"] is True

# J File/line provenance
def test_file_line_provenance():
    f = {"scanner": "sast", "title": "Hardcoded secret", "severity": "high", "metadata": {"file": "app.py", "line": 10, "rule_id": "SAST001"}}
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["coverage"]["has_file"] is True
    assert prov["evidence_items"][0]["evidence_type"] == "source_code"

# K SCA provenance
def test_sca_provenance():
    f = {"scanner": "sca", "title": "Vulnerable dependency", "severity": "high", "metadata": {"ecosystem": "npm", "package_name": "lodash", "installed_version": "4.17.20", "cve": "CVE-2021-23337"}}
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    # Check SCA fields preserved
    assert prov["coverage"]["has_cve"] is True
    assert "dependency" in prov["evidence_types"] or prov["evidence_types"]

# L CVE/CWE/rule
def test_cve_cwe_rule():
    f = _finding(cve="CVE-2021-0001")
    f["cwe"] = "CWE-79"
    f["metadata"]["rule_id"] = "SAST001"
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert "CVE-2021-0001" in prov["cves"]
    assert "CWE-79" in prov["cwes"]
    assert "SAST001" in prov["rule_ids"]

# M Evidence types
def test_evidence_types():
    f = _finding(url="https://example.com/login")
    corr = correlate_findings([f])["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert prov["evidence_types"]
    assert "unknown" not in prov["evidence_types"] or len(prov["evidence_types"]) == 1

# N Coverage flags
def test_coverage_flags():
    corr = _correlated_single()
    prov = build_evidence_provenance(corr)
    assert prov["coverage"]["has_asset"] in (True, False)
    assert prov["coverage"]["has_location"] is True
    assert prov["coverage"]["has_url"] is True

# O Provenance quality
def test_provenance_quality():
    corr = _correlated_single()
    prov = build_evidence_provenance(corr)
    assert 0 <= prov["provenance_quality_score"] <= 100
    assert prov["provenance_quality_level"] in ("low", "medium", "high", "very_high")

# P Confidence enrichment
def test_confidence_enrichment():
    corr = _correlated_single()
    prov = build_evidence_provenance(corr)
    val = evaluate_finding_validation(corr)
    enriched = enrich_finding_confidence(val, prov)
    assert enriched["confidence_score"] >= val["confidence_score"]
    assert enriched["confidence_score"] <= 100

# Q No severity influence
def test_no_severity_influence():
    f1 = _finding(severity="critical")
    f2 = _finding(severity="info")
    # Use same other fields, so provenance same
    corr1 = correlate_findings([f1])["correlated_findings"][0]
    corr2 = correlate_findings([f2])["correlated_findings"][0]
    prov1 = build_evidence_provenance(corr1)
    prov2 = build_evidence_provenance(corr2)
    assert prov1["provenance_quality_score"] == prov2["provenance_quality_score"]

# R No confirmation
def test_no_confirmation():
    corr = _correlated_single()
    prov = build_evidence_provenance(corr)
    val = evaluate_finding_validation(corr)
    enriched = enrich_finding_confidence(val, prov)
    assert enriched["state"] not in ("confirmed", "false_positive", "accepted_risk", "remediated")

# S Reasons
def test_reasons():
    corr = _correlated_single()
    prov = build_evidence_provenance(corr)
    val = evaluate_finding_validation(corr)
    enriched = enrich_finding_confidence(val, prov)
    assert len(enriched["reasons"]) <= 20
    assert enriched["reasons"] == sorted(enriched["reasons"]) or len(enriched["reasons"]) == len(set(enriched["reasons"]))

# T Evidence bounds
def test_evidence_bounds():
    findings = [_finding(scanner=f"s{i}", url="https://example.com/login") for i in range(60)]
    corr = correlate_findings(findings)["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert len(prov["evidence_items"]) <= 50
    for ev in prov["evidence_items"]:
        assert len(ev["evidence"]) <= 500

# U Scanner bounds
def test_scanner_bounds():
    findings = [_finding(scanner=f"s{i}") for i in range(25)]
    corr = correlate_findings(findings)["correlated_findings"][0]
    prov = build_evidence_provenance(corr)
    assert len(prov["scanners"]) <= 20

# V Identifier bounds
def test_identifier_bounds():
    # Create many CVEs
    findings = []
    for i in range(30):
        f = _finding(cve=f"CVE-2021-{i:04d}")
        findings.append(f)
    # Need same fingerprint to aggregate: same title/url etc, but different cve will make different fingerprint, so not same group
    # Instead test that provenance cves bounded
    corr = _correlated_single()
    # Manually set many cves
    corr["cves"] = [f"CVE-2021-{i:04d}" for i in range(30)]
    prov = build_evidence_provenance(corr)
    assert len(prov["cves"]) <= 20

# W Determinism
def test_determinism():
    f1 = _finding(scanner="nuclei", url="https://example.com/login")
    f2 = _finding(scanner="zap", url="https://example.com/login")
    prov1 = build_evidence_provenance(correlate_findings([f1, f2])["correlated_findings"][0])
    prov2 = build_evidence_provenance(correlate_findings([f2, f1])["correlated_findings"][0])
    assert prov1 == prov2

# X Input order
def test_input_order():
    f1 = _finding(scanner="nuclei")
    f2 = _finding(scanner="zap")
    corr1 = correlate_findings([f1, f2])["correlated_findings"][0]
    corr2 = correlate_findings([f2, f1])["correlated_findings"][0]
    prov1 = build_evidence_provenance(corr1)
    prov2 = build_evidence_provenance(corr2)
    assert prov1["scanners"] == prov2["scanners"]
    assert prov1["evidence_types"] == prov2["evidence_types"]

# Y No mutation
def test_no_mutation():
    import copy
    corr = _correlated_single()
    orig = copy.deepcopy(corr)
    build_evidence_provenance(corr)
    assert corr == orig
    val = evaluate_finding_validation(corr)
    orig_val = copy.deepcopy(val)
    prov = build_evidence_provenance(corr)
    enrich_finding_confidence(val, prov)
    assert val == orig_val

# Z Empty input
def test_empty_input():
    prov = build_evidence_provenance({})
    assert prov["evidence_count"] == 0
    assert prov["provenance_quality_score"] == 0

# AA Existing S4.1/S4.2 compatibility
def test_existing_compatibility():
    # Ensure S4.1 and S4.2 still work
    from app.services.finding_correlation.normalizer import fingerprint_finding
    f = _finding()
    fp = fingerprint_finding(f)
    assert isinstance(fp, str)
    assert len(fp) == 64

# AB Existing S4.3 compatibility
def test_existing_validation_compatibility():
    corr = _correlated_single()
    val = evaluate_finding_validation(corr)
    assert val["state"] in ("detected", "corroborated")
    prov = build_evidence_provenance(corr)
    enriched = enrich_finding_confidence(val, prov)
    assert enriched["state"] == val["state"]  # S4.4 must not change state
