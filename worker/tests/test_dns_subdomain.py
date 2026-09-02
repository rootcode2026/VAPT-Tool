import pytest

from app.persistence import asset_metadata, infer_asset_type, infer_asset_value
from app.scanner.manager import ScannerManager
from app.scanner.parsers.dns_parser import DNSParser
from app.scanner.parsers.subdomain_parser import SubdomainParser
from app.scanner.pipeline import ScannerPipeline
from app.scanner.scanners.dns import DNSScanner
from app.scanner.scanners.subdomain import SubdomainScanner

from tests.helpers import load_fixture


def test_dns_parser_normalizes_supported_record_types():
    result = DNSParser().parse(load_fixture("dns.jsonl"))

    assert result["scanner"] == "dns"
    assert result["findings"] == []

    by_type = {}
    for asset in result["assets"]:
        by_type.setdefault(asset["type"], []).append(asset)

    assert by_type["domain"][0]["value"] == "internal.test"
    assert by_type["ip"][0]["value"] == "10.0.0.8"
    assert by_type["ipv6"][0]["value"] == "2001:db8::8"

    cname = by_type["dns_cname"][0]
    assert cname["value"] == "internal.test"
    assert cname["metadata"]["target"] == "www.internal.test"

    mx = by_type["dns_mx"][0]
    assert mx["value"] == "mail.internal.test"
    assert mx["metadata"]["priority"] == 10

    assert by_type["dns_ns"][0]["value"] == "ns1.internal.test"
    assert by_type["dns_txt"][0]["value"] == "v=spf1 -all"

    soa = by_type["dns_soa"][0]
    assert soa["value"] == "ns1.internal.test"
    assert soa["metadata"]["serial"] == 2026090201

    subdomain_values = {
        asset["value"] for asset in by_type["subdomain"]
    }
    assert "www.internal.test" in subdomain_values
    assert "mail.internal.test" in subdomain_values
    assert "ns1.internal.test" in subdomain_values


def test_dns_parser_empty_output_returns_no_findings():
    result = DNSParser().parse("  ")

    assert result == {
        "scanner": "dns",
        "assets": [],
        "findings": [],
    }


def test_dns_parser_invalid_output_raises_value_error():
    with pytest.raises(ValueError, match="Invalid DNS JSON output"):
        DNSParser().parse("dns lookup started\nno json here")


def test_subdomain_parser_normalizes_hosts_and_metadata():
    result = SubdomainParser().parse(load_fixture("subdomain.jsonl"))

    assert result["scanner"] == "subdomain"
    assert result["findings"] == []
    assert [asset["type"] for asset in result["assets"]] == [
        "subdomain",
        "subdomain",
        "subdomain",
    ]
    assert [asset["value"] for asset in result["assets"]] == [
        "www.internal.test",
        "api.internal.test",
        "mail.internal.test",
    ]
    assert result["assets"][0]["metadata"]["source"] == "crtsh"
    assert result["assets"][1]["metadata"]["resolved_ip"] == "10.0.0.9"


def test_subdomain_parser_invalid_output_raises_value_error():
    with pytest.raises(ValueError, match="Invalid subdomain JSON output"):
        SubdomainParser().parse("enumerating hosts")


def test_dns_and_subdomain_hostname_identity_converges():
    dns_assets = DNSParser().parse(load_fixture("dns.jsonl"))["assets"]
    sub_assets = SubdomainParser().parse(
        load_fixture("subdomain.jsonl")
    )["assets"]

    dns_mail = next(
        asset
        for asset in dns_assets
        if asset["type"] == "subdomain"
        and asset["value"] == "mail.internal.test"
    )
    sub_mail = next(
        asset
        for asset in sub_assets
        if asset["value"] == "mail.internal.test"
    )

    assert infer_asset_type(dns_mail) == infer_asset_type(sub_mail)
    assert infer_asset_value(dns_mail) == infer_asset_value(sub_mail)
    assert asset_metadata(sub_mail)["source"] == "crtsh"


def test_pipeline_dns_fixture_produces_assets_without_findings(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("dns.jsonl"),
    )

    result = pipeline.run("dns", "internal.test")

    assert result["scanner"] == "dns"
    assert result["parsed_result"]["findings"] == []
    assert result["findings"] == []
    assert any(
        asset["type"] == "ip" and asset["value"] == "10.0.0.8"
        for asset in result["parsed_result"]["assets"]
    )


def test_pipeline_subdomain_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("subdomain.jsonl"),
    )

    result = pipeline.run("subdomain", "internal.test")

    assert result["scanner"] == "subdomain"
    assert result["findings"] == []
    assert len(result["parsed_result"]["assets"]) == 3


def test_dns_scanner_rejects_ip_targets():
    scanner = DNSScanner()
    scanner.runner = type("R", (), {"run": staticmethod(lambda **k: "")})()

    with pytest.raises(ValueError, match="domain targets"):
        scanner.scan("10.0.0.8")


def test_subdomain_scanner_rejects_ip_targets():
    scanner = SubdomainScanner()
    scanner.runner = type("R", (), {"run": staticmethod(lambda **k: "")})()

    with pytest.raises(ValueError, match="domain targets"):
        scanner.scan("10.0.0.8")


def test_manager_rejects_subdomain_scanner_for_ip_target_type():
    with pytest.raises(ValueError, match="does not support"):
        ScannerManager().run(
            scanner="subdomain",
            target="internal.test",
            target_type="ip",
        )
