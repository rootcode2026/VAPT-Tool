from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding, correlation_key
import copy

def _base_finding(**overrides):
    base = {
        "scanner": "nuclei",
        "title": "SQL Injection vulnerability",
        "description": "test",
        "severity": "high",
        "score": 75,
        "status": "open",
        "evidence": "test",
        "remediation": "fix",
        "cve": "CVE-2021-23337",
        "cwe": "CWE-79",
        "metadata": {"rule_id": "SAST001", "uri": "https://example.com/path?query=1#frag", "host": "EXAMPLE.COM.", "port": "443"},
        "asset_id": "a1",
    }
    base.update(overrides)
    return base

# Text normalization
def test_whitespace():
    f = _base_finding(title="  SQL Injection   vulnerability\n")
    n = normalize_finding(f)
    assert n["normalized_title"] == "SQL Injection vulnerability"

def test_newlines():
    f = _base_finding(title="SQL\nInjection\rvulnerability")
    n = normalize_finding(f)
    assert n["normalized_title"] == "SQL Injection vulnerability"

# Severity
def test_severity_variants():
    assert normalize_finding(_base_finding(severity="CRITICAL"))["severity"] == "critical"
    assert normalize_finding(_base_finding(severity="High"))["severity"] == "high"
    assert normalize_finding(_base_finding(severity="informational"))["severity"] == "info"
    assert normalize_finding(_base_finding(severity=""))["severity"] == "info"
    assert normalize_finding(_base_finding(severity="unknown"))["severity"] == "info"

# CVE
def test_cve_lowercase():
    assert normalize_finding(_base_finding(cve="cve-2021-23337"))["cve"] == "CVE-2021-23337"

def test_cve_canonical():
    assert normalize_finding(_base_finding(cve="CVE-2021-23337"))["cve"] == "CVE-2021-23337"

def test_cve_missing():
    assert normalize_finding(_base_finding(cve=None))["cve"] is None

def test_cwe():
    assert normalize_finding(_base_finding(cwe="cwe-79"))["cwe"] == "CWE-79"
    assert normalize_finding(_base_finding(cwe="CWE-79"))["cwe"] == "CWE-79"

def test_rule_id():
    assert normalize_finding(_base_finding(metadata={"rule_id": "sast001"}))["rule_id"] == "SAST001"
    assert normalize_finding(_base_finding(metadata={"rule_id": " SAST001 "}))["rule_id"] == "SAST001"

# URL
def test_url_equivalence():
    f1 = _base_finding(metadata={"uri": "https://EXAMPLE.COM:443/path"})
    f2 = _base_finding(metadata={"uri": "https://example.com/path"})
    assert normalize_finding(f1)["url"] == normalize_finding(f2)["url"]
    # fragment should not affect
    f3 = _base_finding(metadata={"uri": "https://example.com/path#frag"})
    assert normalize_finding(f3)["url"] == normalize_finding(f2)["url"]

# Host
def test_host_normalization():
    f = _base_finding(metadata={"host": "EXAMPLE.COM."})
    assert normalize_finding(f)["hostname"] == "example.com"
    f2 = _base_finding(metadata={"host": "example.com"})
    assert normalize_finding(f)["hostname"] == normalize_finding(f2)["hostname"]

# IPv4
def test_ipv4():
    f = _base_finding(metadata={"ip": "192.168.1.1"})
    assert normalize_finding(f)["ip"] == "192.168.1.1"
    f2 = _base_finding(metadata={"ip": " 192.168.1.1 "})
    assert normalize_finding(f2)["ip"] == "192.168.1.1"

# IPv6
def test_ipv6():
    f = _base_finding(metadata={"ip": "2001:0db8:0000:0000:0000:0000:0000:0008"})
    n = normalize_finding(f)
    assert n["ip"] == "2001:db8::8"
    f2 = _base_finding(metadata={"ip": "2001:db8::8"})
    assert normalize_finding(f2)["ip"] == "2001:db8::8"

# Port
def test_port():
    assert normalize_finding(_base_finding(metadata={"port": "443"}))["port"] == "443"
    assert normalize_finding(_base_finding(metadata={"port": 443}))["port"] == "443"
    assert normalize_finding(_base_finding(metadata={"port": "443/tcp"}))["port"] == "443"

# Evidence
def test_evidence_line_endings():
    f = _base_finding(evidence="line1\r\nline2\rline3\nline4")
    ev = normalize_finding(f)["normalized_evidence"]
    assert "\r" not in ev

def test_evidence_bounded():
    f = _base_finding(evidence="a" * 1000)
    assert len(normalize_finding(f)["normalized_evidence"]) <= 500

# Fingerprint determinism
def test_same_finding_same_fingerprint():
    f = _base_finding()
    assert fingerprint_finding(f) == fingerprint_finding(f)

def test_repeated_execution_same():
    f = _base_finding()
    f2 = copy.deepcopy(f)
    assert fingerprint_finding(f) == fingerprint_finding(f2)

# Fingerprint sensitivity
def test_different_url_different_fingerprint():
    f1 = _base_finding(metadata={"uri": "https://example.com/path"})
    f2 = _base_finding(metadata={"uri": "https://example.com/other"})
    assert fingerprint_finding(f1) != fingerprint_finding(f2)

def test_different_port_different():
    f1 = _base_finding(metadata={"port": "80"})
    f2 = _base_finding(metadata={"port": "443"})
    assert fingerprint_finding(f1) != fingerprint_finding(f2)

def test_different_file_different():
    f1 = _base_finding(metadata={"file": "a.py", "line": 10})
    f2 = _base_finding(metadata={"file": "b.py", "line": 10})
    assert fingerprint_finding(f1) != fingerprint_finding(f2)

def test_different_rule_different():
    f1 = _base_finding(metadata={"rule_id": "SAST001"})
    f2 = _base_finding(metadata={"rule_id": "SAST002"})
    assert fingerprint_finding(f1) != fingerprint_finding(f2)

# Scanner independence
def test_scanner_independence():
    f1 = _base_finding(scanner="nuclei", title="X", metadata={"uri": "https://example.com/path", "rule_id": "R1"})
    f2 = _base_finding(scanner="zap", title="X", metadata={"uri": "https://example.com/path", "rule_id": "R1"})
    # Same logical finding different scanner should be same fingerprint
    assert fingerprint_finding(f1) == fingerprint_finding(f2)

# Volatile fields
def test_volatile_fields_no_change():
    f1 = _base_finding()
    f1["scan_id"] = "scan1"
    f1["metadata"]["timestamp"] = "2024-01-01"
    f2 = _base_finding()
    f2["scan_id"] = "scan2"
    f2["metadata"]["timestamp"] = "2025-01-01"
    assert fingerprint_finding(f1) == fingerprint_finding(f2)

# Missing location
def test_missing_location_not_global_collapse():
    f1 = _base_finding(title="SQL Injection", metadata={})
    f2 = _base_finding(title="XSS", metadata={})
    # Different titles should not collapse even without location
    assert fingerprint_finding(f1) != fingerprint_finding(f2)
    # Same title without location will have same fingerprint (expected), but we ensure not all collapse
    f3 = _base_finding(title="Same", metadata={})
    f4 = _base_finding(title="Same", metadata={})
    assert fingerprint_finding(f3) == fingerprint_finding(f4)

# Correlation key
def test_correlation_key():
    f1 = _base_finding(metadata={"uri": "https://example.com/a", "rule_id": "R1"})
    f2 = _base_finding(metadata={"uri": "https://example.com/b", "rule_id": "R1"})
    # Different URL should have different fingerprint but same correlation key (pattern)
    assert fingerprint_finding(f1) != fingerprint_finding(f2)
    assert correlation_key(f1) == correlation_key(f2)
