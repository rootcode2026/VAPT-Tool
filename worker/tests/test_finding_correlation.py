import copy
from app.services.finding_correlation.correlator import correlate_findings

def _finding(scanner="nuclei", title="SQL Injection", severity="high", cve="CVE-2021-23337", url="https://example.com/login?id=1", host=None, port=None, file=None, line=None, evidence="test", project_id="p1", **extra):
    f = {
        "scanner": scanner,
        "title": title,
        "description": "test",
        "severity": severity,
        "score": 75 if severity=="high" else 50,
        "status": "open",
        "evidence": evidence,
        "remediation": "fix",
        "cve": cve,
        "cwe": "CWE-79",
        "metadata": {"uri": url, "host": host, "port": port, "file": file, "line": line, "rule_id": "SAST001"},
        "asset_id": None,
    }
    if project_id:
        f["project_id"] = project_id
        f["metadata"]["project_id"] = project_id
    f.update(extra)
    return f

# A. Same fingerprint
def test_same_fingerprint_one_finding():
    f1 = _finding()
    f2 = _finding()
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 1
    assert res["duplicate_count"] == 1

# B. Cross-scanner
def test_cross_scanner():
    f1 = _finding(scanner="nuclei")
    f2 = _finding(scanner="zap")
    res = correlate_findings([f1, f2])
    cf = res["correlated_findings"][0]
    assert cf["scanner_count"] == 2
    assert set(cf["scanners"]) == {"nuclei", "zap"}

# C. Same scanner duplicate
def test_same_scanner_duplicate():
    f1 = _finding(scanner="nuclei")
    f2 = _finding(scanner="nuclei")
    res = correlate_findings([f1, f2])
    cf = res["correlated_findings"][0]
    assert cf["scanner_count"] == 1
    assert cf["finding_count"] == 2

# D. Different URLs
def test_different_urls():
    f1 = _finding(url="https://example.com/login")
    f2 = _finding(url="https://example.com/admin")
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# E. Different hosts
def test_different_hosts():
    f1 = _finding(host="example.com")
    f2 = _finding(host="other.com")
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# F. Different ports
def test_different_ports():
    f1 = _finding(port="80")
    f2 = _finding(port="443")
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# G. Different SAST files
def test_different_sast_files():
    f1 = _finding(file="a.py", line=10)
    f2 = _finding(file="b.py", line=10)
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# H. Same correlation_key different location
def test_same_correlation_key_different_location():
    f1 = _finding(title="SQL Injection", url="https://example.com/login", cve=None)
    f2 = _finding(title="SQL Injection", url="https://example.com/admin", cve=None)
    # correlation_key will be same (title), but fingerprint different due to url
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# I. Severity aggregation
def test_severity_aggregation():
    f1 = _finding(severity="medium")
    f2 = _finding(severity="high")
    res = correlate_findings([f1, f2])
    assert res["correlated_findings"][0]["severity"] == "high"
    f3 = _finding(severity="high")
    f4 = _finding(severity="critical")
    res2 = correlate_findings([f3, f4])
    assert res2["correlated_findings"][0]["severity"] == "critical"

# J. Score aggregation
def test_score_aggregation():
    f1 = _finding(severity="medium", title="X")
    f1["score"] = 50
    f2 = _finding(severity="high", title="X")
    f2["score"] = 75
    res = correlate_findings([f1, f2])
    assert res["correlated_findings"][0]["score"] == 75

# K. CVE aggregation
def test_cve_aggregation():
    f1 = _finding(cve="CVE-2021-0001")
    f2 = _finding(cve="CVE-2021-0002")
    # Need same fingerprint to aggregate, so same title/url etc but different cve -> different fingerprint, so not same group
    # To test CVE aggregation, use same fingerprint but different CVE? Actually fingerprint includes cve, so different CVE -> different fingerprint, not same group
    # Instead, test that correlated finding collects unique CVEs when same fingerprint? But fingerprint includes cve, so different CVE won't be same group
    # For now, test that when we have same logical finding with same CVE, it's deduped
    f1 = _finding(cve="CVE-2021-0001", url="https://example.com/a")
    f2 = _finding(cve="CVE-2021-0001", url="https://example.com/a")
    res = correlate_findings([f1, f2])
    assert res["correlated_findings"][0]["cves"] == ["CVE-2021-0001"]

# L. CWE aggregation
def test_cwe_aggregation():
    f1 = _finding()
    f1["cwe"] = "CWE-79"
    f2 = _finding()
    f2["cwe"] = "CWE-79"
    res = correlate_findings([f1, f2])
    assert res["correlated_findings"][0]["cwes"] == ["CWE-79"]

# M. Rule aggregation
def test_rule_aggregation():
    f1 = _finding()
    f1["metadata"]["rule_id"] = "SAST001"
    f2 = _finding()
    f2["metadata"]["rule_id"] = "SAST001"
    res = correlate_findings([f1, f2])
    assert res["correlated_findings"][0]["rule_ids"] == ["SAST001"]

# N. Evidence aggregation
def test_evidence_aggregation():
    f1 = _finding(scanner="nuclei", evidence="ev1")
    f2 = _finding(scanner="zap", evidence="ev2")
    res = correlate_findings([f1, f2])
    ev = res["correlated_findings"][0]["evidence"]
    assert len(ev) == 2
    # Deduplicate identical evidence
    f3 = _finding(scanner="nuclei", evidence="same")
    f4 = _finding(scanner="nuclei", evidence="same")
    res2 = correlate_findings([f3, f4])
    assert len(res2["correlated_findings"][0]["evidence"]) == 1
    # Deterministic ordering
    assert ev[0]["scanner"] == "nuclei"

# O. Source finding references
def test_source_findings():
    f1 = _finding(scanner="nuclei")
    res = correlate_findings([f1])
    src = res["correlated_findings"][0]["source_findings"][0]
    assert src["scanner"] == "nuclei"
    assert "fingerprint" in src
    assert src["fingerprint"] != ""

# P. Missing location
def test_missing_location_not_collapse():
    f1 = _finding(title="SQL Injection", url=None, host=None, cve=None)
    f1["metadata"] = {}
    f2 = _finding(title="XSS", url=None, host=None, cve=None)
    f2["metadata"] = {}
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# Q. Scanner independence
def test_scanner_independence():
    f1 = _finding(scanner="nuclei", title="X", url="https://example.com/a")
    f2 = _finding(scanner="zap", title="X", url="https://example.com/a")
    from app.services.finding_correlation.normalizer import fingerprint_finding
    assert fingerprint_finding(f1) == fingerprint_finding(f2)
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 1

# R. Project isolation
def test_project_isolation():
    f1 = _finding(project_id="p1")
    f2 = _finding(project_id="p2")
    res = correlate_findings([f1, f2])
    assert res["total_correlated_findings"] == 2

# S. Deterministic result
def test_deterministic():
    f1 = _finding(title="A")
    f2 = _finding(title="B")
    res1 = correlate_findings([f1, f2])
    res2 = correlate_findings([f2, f1])
    assert res1["correlated_findings"] == res2["correlated_findings"]

# T. Empty input
def test_empty():
    res = correlate_findings([])
    assert res["total_correlated_findings"] == 0
    assert res["correlated_findings"] == []

# U. Single finding
def test_single():
    f = _finding()
    res = correlate_findings([f])
    assert res["total_correlated_findings"] == 1
    assert res["correlated_findings"][0]["finding_count"] == 1

# V. No mutation
def test_no_mutation():
    f = _finding()
    orig = copy.deepcopy(f)
    correlate_findings([f])
    assert f == orig
