from app.api.routes.scanners import SCANNERS
from app.schemas.finding import FindingResponse


def test_scanner_catalog_exposes_supported_scanners():
    names = [scanner["name"] for scanner in SCANNERS]

    assert names == [
        "nmap",
        "nuclei",
        "http_fingerprint",
        "zap",
        "nikto",
        "tls",
        "dns",
        "subdomain",
    ]


def test_finding_response_includes_metadata_without_breaking_core_fields():
    payload = FindingResponse(
        id="f1",
        scan_id="s1",
        target_id="t1",
        scanner="zap",
        title="CSP Header Not Set",
        description="Missing CSP",
        severity="medium",
        score=50,
        status="open",
        evidence="",
        remediation="Set CSP",
        cve=None,
        cwe="CWE-693",
        asset_id="a1",
        extra_data={"plugin_id": "10038", "uri": "https://internal.test/"},
    ).model_dump()

    assert payload["metadata"]["plugin_id"] == "10038"
    assert payload["title"] == "CSP Header Not Set"
    assert payload["asset_id"] == "a1"
    assert "extra_data" not in payload
