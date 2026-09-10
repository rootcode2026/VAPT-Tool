"""D8 fingerprint parity vectors: backend canonical fingerprint == worker fingerprint.

The worker normalizer is authoritative. The backend D8 implementation must
produce byte-identical fingerprints for the same logical finding; this test
fails loudly on either side's drift.
"""

import os
import sys

from app.services import finding_lifecycle as lc

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_worker_fingerprint_fn():
    """Import the worker normalizer despite the backend `app` package shadow.

    Backend `app` is imported first (above); we temporarily swap sys.modules
    + sys.path to load the worker implementation, then restore. The returned
    function object remains usable afterwards.
    """
    saved_modules = dict(sys.modules)
    saved_path = list(sys.path)
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]
    sys.path.insert(0, os.path.join(REPO_ROOT, "worker"))
    try:
        import app.services.finding_correlation.normalizer as wnorm  # type: ignore
        return wnorm.fingerprint_finding
    finally:
        for mod in [m for m in list(sys.modules) if m == "app" or m.startswith("app.")]:
            del sys.modules[mod]
        sys.modules.update(saved_modules)
        sys.path[:] = saved_path


fingerprint_finding = _load_worker_fingerprint_fn()


class _Row:
    def __init__(self, title, scanner="nmap", cve=None, cwe=None, meta=None):
        self.title = title
        self.scanner = scanner
        self.cve = cve
        self.cwe = cwe
        self.extra_data = meta or {}


def _worker_input(title, scanner="nmap", cve=None, cwe=None, meta=None):
    return {"title": title, "scanner": scanner, "cve": cve, "cwe": cwe, "metadata": dict(meta or {})}


def test_vector_network_finding_matches_worker():
    meta = {"hostname": "example.com", "port": 443, "ip": "93.184.216.34"}
    row = _Row("TLS certificate expires soon", cve=None, cwe="CWE-327", meta=meta)
    assert lc.d8_fingerprint(lc.d8_finding_input(row)) == fingerprint_finding(_worker_input("TLS certificate expires soon", cwe="CWE-327", meta=meta))


def test_vector_cve_rule_file_matches_worker():
    meta = {"rule_id": "python-sql-injection", "file": "app/db.py", "line": 42, "cve": "CVE-2021-23337"}
    row = _Row("Possible SQL injection", scanner="sast", meta=meta)
    assert lc.d8_fingerprint(lc.d8_finding_input(row)) == fingerprint_finding(_worker_input("Possible SQL injection", scanner="sast", meta=meta))


def test_vector_url_param_matches_worker():
    meta = {"url": "https://example.com/search", "parameter": "q"}
    row = _Row("Reflected XSS", scanner="zap", meta=meta)
    assert lc.d8_fingerprint(lc.d8_finding_input(row)) == fingerprint_finding(_worker_input("Reflected XSS", scanner="zap", meta=meta))


def test_vector_title_only_matches_worker():
    row = _Row("Open port 22")
    assert lc.d8_fingerprint(lc.d8_finding_input(row)) == fingerprint_finding(_worker_input("Open port 22"))


def test_vector_determinism_and_case():
    row = _Row("  Open   port 22\n", meta={"port": "22"})
    a = lc.d8_fingerprint(lc.d8_finding_input(row))
    b = lc.d8_fingerprint(lc.d8_finding_input(_Row("Open port 22", meta={"port": 22})))
    assert a == b


def test_evaluator_cases():
    base = "abc123"
    assert lc.evaluate_retest_verification(base, {base}, "completed")[0] == "failed"
    assert lc.evaluate_retest_verification(base, {"other"}, "completed")[0] == "passed"
    assert lc.evaluate_retest_verification(base, set(), "completed")[0] == "passed"
    assert lc.evaluate_retest_verification(base, set(), "failed")[0] == "error"
    assert lc.evaluate_retest_verification(base, set(), "running")[0] == "error"
    assert lc.evaluate_retest_verification(base, set(), "completed", parser_ok=False)[0] == "error"
    assert lc.evaluate_retest_verification(base, set(), "completed", completeness="partial")[0] == "error"
    assert lc.evaluate_retest_verification(None, set(), "completed")[0] == "passed"
    # Scanner failure is never passed even with empty detections.
    r, note = lc.evaluate_retest_verification(base, set(), "failed")
    assert r == "error" and "did not complete" in note
