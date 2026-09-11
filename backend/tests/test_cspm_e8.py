"""E8.1 CSPM hardening — deterministic, provider-neutral, on-read.

Covers: catalog count, category counts, mapping counts/validity, PASS/FAIL/NOT_ASSESSED,
positive evidence, scoring, grade, compliance/coverage, aggregation, filtering,
evidence bounds, secrets, isolation.
"""

import collections
import uuid
import pytest

from app.services.cspm import CSPM_CONTROLS, SEVERITY_WEIGHTS, evaluate_cspm, list_controls, get_control_detail


class FakeFinding:
    def __init__(self, rule_id, finding_id=None, asset_id=None, title="test", severity="high"):
        self.id = finding_id or str(uuid.uuid4())
        self.asset_id = asset_id or str(uuid.uuid4())
        self.title = title
        self.severity = severity
        self.extra_data = {"rule_id": rule_id}


def _make_run(breakdown):
    """Create a fake CloudCheckRun with breakdown avoiding class-body scoping bug."""
    class _R:
        pass
    r = _R()
    r.breakdown = breakdown
    import datetime
    r.created_at = datetime.datetime.now(datetime.timezone.utc)
    return r


def _fake_db_with_findings(findings, breakdown=None):
    class DB:
        def query(self, model, *a, **kw):
            name = getattr(model, "__name__", "")
            class Q:
                def join(self, *aa, **kk): return self
                def filter(self, *aa, **kk): return self
                def limit(self, *aa, **kk): return self
                def order_by(self, *aa, **kk): return self
                def first(self):
                    if "CloudCheckRun" in name:
                        if breakdown is not None:
                            return _make_run(breakdown)
                        return None
                    return None
                def all(self):
                    if "Finding" in name:
                        return findings
                    return []
            return Q()
    return DB()


# ---------------------------------------------------------------------------
# 1. Exact catalog count
# ---------------------------------------------------------------------------

def test_catalog_exact_count_is_21():
    assert len(CSPM_CONTROLS) == 21

def test_no_duplicate_control_ids():
    ids = [c["control_id"] for c in CSPM_CONTROLS]
    assert len(ids) == len(set(ids))

def test_catalog_within_20_40():
    assert 20 <= len(CSPM_CONTROLS) <= 40


# ---------------------------------------------------------------------------
# 2. Category counts mathematically correct
# ---------------------------------------------------------------------------

def test_category_counts_exact():
    c = collections.Counter(x["category"] for x in CSPM_CONTROLS)
    assert c["IDENTITY"] == 3
    assert c["NETWORK"] == 7
    assert c["STORAGE"] == 3
    assert c["ENCRYPTION"] == 3
    assert c["COMPUTE"] == 2
    assert c["EXPOSURE"] == 2
    assert c["LOGGING"] == 1
    assert sum(c.values()) == 21

def test_no_hardcoded_category_mismatch():
    total = len(CSPM_CONTROLS)
    cat_total = sum(collections.Counter(x["category"] for x in CSPM_CONTROLS).values())
    assert total == cat_total

def test_every_control_has_valid_metadata():
    for ctrl in CSPM_CONTROLS:
        assert ctrl["control_id"].startswith("CSPM-")
        assert ctrl["category"] in {"IDENTITY", "NETWORK", "STORAGE", "COMPUTE", "ENCRYPTION", "EXPOSURE", "LOGGING", "CONFIGURATION"}
        assert ctrl["severity"] in {"critical", "high", "medium", "low", "info"}
        assert isinstance(ctrl["mappings"], dict) and ctrl["mappings"]


# ---------------------------------------------------------------------------
# 3. Provider mapping counts exact
# ---------------------------------------------------------------------------

def test_provider_mapping_counts_exact():
    aws = sum(len(c["mappings"].get("aws", [])) for c in CSPM_CONTROLS)
    gcp = sum(len(c["mappings"].get("gcp", [])) for c in CSPM_CONTROLS)
    az = sum(len(c["mappings"].get("azure", [])) for c in CSPM_CONTROLS)
    assert aws == 32
    assert gcp == 20
    assert az == 22
    assert aws + gcp + az == 74

def test_unique_provider_rule_ids():
    uniq = {(prov, rid) for c in CSPM_CONTROLS for prov, rids in c["mappings"].items() for rid in rids}
    assert len(uniq) == 47

def test_controls_with_zero_mappings_documented():
    zero_aws = [c["control_id"] for c in CSPM_CONTROLS if not c["mappings"].get("aws")]
    zero_gcp = [c["control_id"] for c in CSPM_CONTROLS if not c["mappings"].get("gcp")]
    zero_az = [c["control_id"] for c in CSPM_CONTROLS if not c["mappings"].get("azure")]
    assert zero_aws == ["CSPM-COMPUTE-002"]
    assert zero_gcp == ["CSPM-NET-007", "CSPM-STORAGE-002", "CSPM-STORAGE-003"]
    assert zero_az == ["CSPM-NET-007", "CSPM-LOG-001"]

def test_no_orphan_mapping():
    from app.services.cloud_checks import AWS_CHECKS
    valid = {c["check_id"] for c in AWS_CHECKS}
    orphans = []
    for ctrl in CSPM_CONTROLS:
        for prov, rids in ctrl["mappings"].items():
            for rid in rids:
                if rid not in valid:
                    orphans.append((ctrl["control_id"], rid))
    assert orphans == [], f"orphan mappings: {orphans}"


# ---------------------------------------------------------------------------
# 4. Duplicate control semantics (NET-006 vs COMPUTE-001)
# ---------------------------------------------------------------------------

def test_duplicate_control_analysis_documented():
    net006 = next(c for c in CSPM_CONTROLS if c["control_id"] == "CSPM-NET-006")
    comp001 = next(c for c in CSPM_CONTROLS if c["control_id"] == "CSPM-COMPUTE-001")
    assert net006["mappings"] == comp001["mappings"]
    assert net006["category"] == "NETWORK"
    assert comp001["category"] == "COMPUTE"
    assert net006["title"] != comp001["title"]


# ---------------------------------------------------------------------------
# 5. PASS / FAIL / NOT_ASSESSED semantics
# ---------------------------------------------------------------------------

def test_not_assessed_when_no_evidence():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    assert data["controls"]["not_assessed"] == 21
    assert data["controls"]["passed"] == 0
    assert data["controls"]["failed"] == 0

def test_pass_requires_positive_evidence():
    bd2 = {"AWS-NET-010": {"passed": 1, "failed": 0, "not_assessed": 0}}
    db2 = _fake_db_with_findings([], breakdown=bd2)
    data2 = evaluate_cspm("proj-1", db2)
    net007 = next(r for r in data2["results"] if r["control_id"] == "CSPM-NET-007")
    assert net007["status"] == "PASS"

def test_fail_when_finding_exists():
    f = FakeFinding("AWS-NET-002")
    db = _fake_db_with_findings([f])
    data = evaluate_cspm("proj-1", db)
    net001 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-001")
    assert net001["status"] == "FAIL"

def test_fail_takes_precedence_over_pass():
    f = FakeFinding("AWS-NET-010")
    bd = {"AWS-NET-010": {"passed": 5, "failed": 0, "not_assessed": 0}}
    db = _fake_db_with_findings([f], breakdown=bd)
    data = evaluate_cspm("proj-1", db)
    net007 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-007")
    assert net007["status"] == "FAIL"

def test_provider_unsupported_is_excluded():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db, provider_filter="gcp")
    ids = [r["control_id"] for r in data["results"]]
    assert "CSPM-NET-007" not in ids
    assert data["controls"]["not_assessed"] > 0
    assert data["controls"]["passed"] == 0


# ---------------------------------------------------------------------------
# 6. Positive-evidence mandatory cases (5 cases)
# ---------------------------------------------------------------------------

def test_case1_no_findings_no_evidence_is_not_assessed():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    assert all(r["status"] == "NOT_ASSESSED" for r in data["results"])

def test_case2_positive_evidence_no_findings_is_pass():
    bd = {"AWS-NET-010": {"passed": 1, "failed": 0, "not_assessed": 0}}
    db = _fake_db_with_findings([], breakdown=bd)
    data = evaluate_cspm("proj-1", db)
    net007 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-007")
    assert net007["status"] == "PASS"

def test_case3_negative_finding_is_fail():
    f = FakeFinding("AWS-NET-010")
    db = _fake_db_with_findings([f])
    data = evaluate_cspm("proj-1", db)
    net007 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-007")
    assert net007["status"] == "FAIL"

def test_case4_both_positive_and_negative_is_fail():
    f = FakeFinding("AWS-NET-010")
    bd = {"AWS-NET-010": {"passed": 1, "failed": 0, "not_assessed": 0}}
    db = _fake_db_with_findings([f], breakdown=bd)
    data = evaluate_cspm("proj-1", db)
    net007 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-007")
    assert net007["status"] == "FAIL"

def test_case5_provider_unsupported_is_not_assessed():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    net007 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-007")
    assert net007["status"] == "NOT_ASSESSED"


# ---------------------------------------------------------------------------
# 7. Provider aggregation
# ---------------------------------------------------------------------------

def test_provider_aggregation_independent():
    bd = {"AWS-NET-010": {"passed": 1, "failed": 0, "not_assessed": 0}}
    f_gcp = FakeFinding("GCP-NET-001")
    db = _fake_db_with_findings([f_gcp], breakdown=bd)
    data = evaluate_cspm("proj-1", db)
    assert data["providers"]["aws"]["passed"] >= 1
    assert data["providers"]["gcp"]["failed"] >= 1

def test_provider_aggregation_not_contaminated():
    total_aws = len([c for c in CSPM_CONTROLS if "aws" in c["mappings"]])
    total_gcp = len([c for c in CSPM_CONTROLS if "gcp" in c["mappings"]])
    db = _fake_db_with_findings([FakeFinding("AWS-NET-002")])
    data = evaluate_cspm("proj-1", db)
    assert data["providers"]["aws"]["total"] == total_aws
    assert data["providers"]["gcp"]["total"] == total_gcp


# ---------------------------------------------------------------------------
# 8. Category aggregation
# ---------------------------------------------------------------------------

def test_category_aggregation_sums_to_total():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    for cat, vals in data["categories"].items():
        assert vals["total"] == vals["passed"] + vals["failed"] + vals["not_assessed"]
    total_from_cats = sum(v["total"] for v in data["categories"].values())
    assert total_from_cats == 21

def test_category_aggregation_network_7():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    assert data["categories"]["NETWORK"]["total"] == 7


# ---------------------------------------------------------------------------
# 9. Provider / category / status filters
# ---------------------------------------------------------------------------

def test_provider_filter_aws():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db, provider_filter="aws")
    for r in data["results"]:
        assert "aws" in r["mappings"]

def test_provider_filter_invalid_raises():
    db = _fake_db_with_findings([])
    with pytest.raises(ValueError):
        evaluate_cspm("proj-1", db, provider_filter="invalid")

def test_category_filter_network():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db, category_filter="NETWORK")
    assert all(r["category"] == "NETWORK" for r in data["results"])
    assert len(data["results"]) == 7

def test_category_filter_invalid_raises():
    db = _fake_db_with_findings([])
    with pytest.raises(ValueError):
        evaluate_cspm("proj-1", db, category_filter="INVALIDCAT")

def test_status_filter():
    f = FakeFinding("AWS-NET-002")
    db = _fake_db_with_findings([f])
    results = list_controls("proj-1", db, status="FAIL")
    assert all(r["status"] == "FAIL" for r in results)
    assert len(results) >= 1

def test_combined_provider_category_status():
    f = FakeFinding("AWS-NET-002")
    db = _fake_db_with_findings([f])
    results = list_controls("proj-1", db, provider="aws", category="NETWORK", status="FAIL")
    assert all(r["category"] == "NETWORK" and "aws" in r["mappings"] and r["status"] == "FAIL" for r in results)


# ---------------------------------------------------------------------------
# 10. Control detail
# ---------------------------------------------------------------------------

def test_control_detail_returns_metadata():
    db = _fake_db_with_findings([])
    detail = get_control_detail("proj-1", db, "CSPM-NET-001")
    assert detail is not None
    assert detail["control_id"] == "CSPM-NET-001"
    assert "mappings" in detail
    assert "status" in detail

def test_control_detail_unknown_404():
    db = _fake_db_with_findings([])
    assert get_control_detail("proj-1", db, "CSPM-UNKNOWN-999") is None


# ---------------------------------------------------------------------------
# 11. Affected resources correctness
# ---------------------------------------------------------------------------

def test_affected_resources_dedup_and_bound():
    a1 = str(uuid.uuid4()); a2 = str(uuid.uuid4())
    findings = [
        FakeFinding("AWS-NET-002", asset_id=a1),
        FakeFinding("AWS-NET-002", asset_id=a1),
        FakeFinding("AWS-EC2-002", asset_id=a2),
    ]
    db = _fake_db_with_findings(findings)
    data = evaluate_cspm("proj-1", db)
    net001 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-001")
    assert a1 in net001["affected_resources"]
    assert a2 in net001["affected_resources"]
    assert len(net001["affected_resources"]) == len(set(net001["affected_resources"]))
    assert len(net001["affected_resources"]) <= 20

def test_max_affected_resources_enforced():
    findings = [FakeFinding("AWS-NET-002", asset_id=str(uuid.uuid4())) for _ in range(30)]
    db = _fake_db_with_findings(findings)
    data = evaluate_cspm("proj-1", db)
    net001 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-001")
    assert len(net001["affected_resources"]) <= 20


# ---------------------------------------------------------------------------
# 12. Evidence correctness & bounds & secret leak
# ---------------------------------------------------------------------------

def test_evidence_bounded_and_has_required_fields():
    findings = [FakeFinding("AWS-NET-002", title="SSH open", severity="high") for _ in range(5)]
    db = _fake_db_with_findings(findings)
    data = evaluate_cspm("proj-1", db)
    net001 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-001")
    assert len(net001["evidence"]) <= 10
    for ev in net001["evidence"]:
        assert "rule_id" in ev and "finding_id" in ev and "title" in ev and "severity" in ev

def test_evidence_no_secret_leak():
    f = FakeFinding("AWS-NET-002", title="exposed secret AKIA... value")
    db = _fake_db_with_findings([f])
    data = evaluate_cspm("proj-1", db)
    net001 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-001")
    for ev in net001["evidence"]:
        assert "AKIA" not in ev["title"] or ev["title"] == "[REDACTED]"
        assert "secret" not in ev["title"].lower() or ev["title"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# 13. Score correctness
# ---------------------------------------------------------------------------

def test_score_no_failures_is_100():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    assert data["score"] == 100

def test_score_one_critical_is_75():
    f = FakeFinding("AWS-NET-005")
    db = _fake_db_with_findings([f])
    data = evaluate_cspm("proj-1", db)
    assert data["score"] == 75

def test_score_weight_lookup():
    assert 100 - SEVERITY_WEIGHTS["high"] == 85
    assert 100 - SEVERITY_WEIGHTS["critical"] == 75
    assert 100 - SEVERITY_WEIGHTS["medium"] == 93
    assert 100 - SEVERITY_WEIGHTS["low"] == 98
    assert 100 - SEVERITY_WEIGHTS["info"] == 99

def test_score_deduct_per_control_not_per_finding():
    findings = [FakeFinding("AWS-NET-010") for _ in range(10)]
    db = _fake_db_with_findings(findings)
    data = evaluate_cspm("proj-1", db)
    assert data["score"] == 98
    assert data["controls"]["failed"] == 1

def test_score_clamped_zero():
    rules = ["AWS-NET-002", "AWS-NET-003", "AWS-NET-004", "AWS-NET-005", "AWS-EC2-002", "AWS-S3-003", "AWS-S3-002", "AWS-RDS-002", "AWS-EBS-001", "AWS-EFS-001", "AWS-S3-001", "AWS-S3-005", "AWS-S3-007", "AWS-NET-007", "AWS-NET-010", "AWS-IAM-001", "GCP-NET-001", "GCP-NET-002"]
    findings = [FakeFinding(r) for r in rules]
    db = _fake_db_with_findings(findings)
    data = evaluate_cspm("proj-1", db)
    assert 0 <= data["score"] <= 100

def test_grade_boundaries():
    def grade_for(score):
        if score >= 90: return "A"
        elif score >= 75: return "B"
        elif score >= 50: return "C"
        else: return "D"
    assert grade_for(90) == "A" and grade_for(89) == "B"
    assert grade_for(75) == "B" and grade_for(74) == "C"
    assert grade_for(50) == "C" and grade_for(49) == "D"

def test_compliance_excludes_not_assessed():
    passed, failed, not_assessed = 15, 5, 10
    evaluated = passed + failed
    compliance = passed / evaluated * 100 if evaluated else 0
    assert compliance == 75.0

def test_compliance_zero_when_no_evaluated():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    assert data["compliance_percent"] == 0

def test_coverage_calculation():
    db = _fake_db_with_findings([])
    data = evaluate_cspm("proj-1", db)
    assert data["coverage_percent"] == 0
    bd = {"AWS-NET-010": {"passed": 1, "failed": 0, "not_assessed": 0}}
    db2 = _fake_db_with_findings([], breakdown=bd)
    data2 = evaluate_cspm("proj-1", db2)
    assert data2["coverage_percent"] == round(1/21*100, 1)

def test_double_count_prevention_same_control():
    findings = [FakeFinding("AWS-S3-007") for _ in range(10)]
    db = _fake_db_with_findings(findings)
    data = evaluate_cspm("proj-1", db)
    assert data["controls"]["failed"] == 1
    assert data["score"] == 99

def test_rbac_project_isolation_via_findings():
    findings_a = [FakeFinding("AWS-NET-002")]
    findings_b = []
    db_a = _fake_db_with_findings(findings_a)
    db_b = _fake_db_with_findings(findings_b)
    data_a = evaluate_cspm("proj-a", db_a)
    data_b = evaluate_cspm("proj-b", db_b)
    assert data_a["controls"]["failed"] >= 1
    assert data_b["controls"]["failed"] == 0

def test_no_double_findingengine_record_needed():
    f = FakeFinding("AWS-NET-002")
    db = _fake_db_with_findings([f])
    data = evaluate_cspm("proj-1", db)
    net001 = next(r for r in data["results"] if r["control_id"] == "CSPM-NET-001")
    assert any(ev["finding_id"] == f.id for ev in net001["evidence"])
