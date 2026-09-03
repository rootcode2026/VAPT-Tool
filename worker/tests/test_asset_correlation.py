from app.asset_intel.correlate import correlate_assets, correlate_parsed_bundle
from app.finding_engine.engine import FindingEngine
from app.scanner.parsers.dns_parser import DNSParser
from app.scanner.parsers.http_fingerprint_parser import HTTPFingerprintParser
from app.scanner.parsers.nmap_parser import NmapParser
from app.scanner.parsers.nuclei_parser import NucleiParser
from app.scanner.parsers.subdomain_parser import SubdomainParser
from app.scanner.parsers.tls_parser import TLSParser
from app.scanner.parsers.zap_parser import ZAPParser

from tests.helpers import load_fixture


def _rel_set(relationships):
    return {
        (
            item["source_type"],
            item["source_value"],
            item["relationship_type"],
            item["target_type"],
            item["target_value"],
        )
        for item in relationships
    }


def _assets_by_type(assets):
    grouped = {}
    for asset in assets:
        grouped.setdefault(asset["type"], []).append(asset["value"])
    return grouped


def test_dns_a_correlation():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    result = correlate_parsed_bundle("dns", parsed["assets"])
    rels = _rel_set(result["relationships"])

    assert (
        "domain",
        "internal.test",
        "resolves_to",
        "ip",
        "10.0.0.8",
    ) in rels


def test_dns_aaaa_correlation():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    result = correlate_parsed_bundle("dns", parsed["assets"])

    assert (
        "domain",
        "internal.test",
        "resolves_to",
        "ipv6",
        "2001:db8::8",
    ) in _rel_set(result["relationships"])


def test_dns_cname_mx_ns_correlation():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    rels = _rel_set(correlate_parsed_bundle("dns", parsed["assets"])["relationships"])

    assert (
        "domain",
        "internal.test",
        "points_to",
        "subdomain",
        "www.internal.test",
    ) in rels
    assert (
        "domain",
        "internal.test",
        "points_to",
        "subdomain",
        "mail.internal.test",
    ) in rels
    assert (
        "domain",
        "internal.test",
        "points_to",
        "subdomain",
        "ns1.internal.test",
    ) in rels
    assert not any("spf" in item[4] for item in rels)


def test_subdomain_correlation_uses_observed_parent():
    parsed = SubdomainParser().parse(load_fixture("subdomain.jsonl"))
    rels = _rel_set(
        correlate_parsed_bundle("subdomain", parsed["assets"])["relationships"]
    )

    assert (
        "domain",
        "internal.test",
        "contains",
        "subdomain",
        "api.internal.test",
    ) in rels


def test_nested_subdomain_requires_observed_intermediate():
    assets = [
        {
            "type": "subdomain",
            "value": "dev.api.internal.test",
            "metadata": {"input": "internal.test"},
        },
        {
            "type": "subdomain",
            "value": "api.internal.test",
            "metadata": {"input": "internal.test"},
        },
    ]
    rels = _rel_set(correlate_parsed_bundle("subdomain", assets)["relationships"])

    assert (
        "domain",
        "internal.test",
        "contains",
        "subdomain",
        "api.internal.test",
    ) in rels
    assert (
        "subdomain",
        "api.internal.test",
        "contains",
        "subdomain",
        "dev.api.internal.test",
    ) in rels
    assert (
        "domain",
        "internal.test",
        "contains",
        "subdomain",
        "dev.api.internal.test",
    ) not in rels


def test_nested_subdomain_without_intermediate_has_no_skip_contains():
    assets = [
        {
            "type": "subdomain",
            "value": "dev.api.internal.test",
            "metadata": {"input": "internal.test"},
        }
    ]
    rels = _rel_set(correlate_parsed_bundle("subdomain", assets)["relationships"])

    assert not any(item[2] == "contains" for item in rels)


def test_nmap_ip_exposes_port_and_port_runs_service():
    parsed = NmapParser().parse(load_fixture("nmap.xml"))
    rels = _rel_set(correlate_parsed_bundle("nmap", parsed["assets"])["relationships"])

    assert ("ip", "10.0.0.8", "exposes", "port", "443") in rels
    assert ("ip", "10.0.0.8", "exposes", "port", "80") in rels
    assert ("port", "443", "runs", "service", "https") in rels
    assert ("port", "80", "runs", "service", "http") in rels


def test_nmap_does_not_infer_dns_or_missing_service():
    assets = [
        {
            "status": "up",
            "addresses": [{"address": "203.0.113.10", "type": "ipv4"}],
            "hostnames": ["internal.test"],
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open"},
            ],
        }
    ]
    result = correlate_parsed_bundle("nmap", assets)
    rels = _rel_set(result["relationships"])

    assert ("ip", "203.0.113.10", "exposes", "port", "22") in rels
    assert not any(item[2] == "runs" for item in rels)
    assert not any(item[2] == "resolves_to" for item in rels)


def test_http_url_serves_technology():
    parsed = HTTPFingerprintParser().parse(load_fixture("http_fingerprint.json"))
    rels = _rel_set(
        correlate_parsed_bundle("http_fingerprint", parsed["assets"])["relationships"]
    )

    assert (
        "url",
        "https://internal.test/",
        "serves",
        "technology",
        "nginx",
    ) in rels


def test_tls_hostname_uses_endpoint():
    parsed = TLSParser().parse(load_fixture("tls.json"))
    rels = _rel_set(correlate_parsed_bundle("tls", parsed["assets"])["relationships"])

    assert any(
        item[0] in {"hostname", "domain"}
        and item[1] == "internal.test"
        and item[2] == "uses"
        and item[3] == "tls_endpoint"
        and item[4] == "internal.test:443"
        for item in rels
    )


def test_zap_and_nuclei_url_canonicalization_converges():
    zap = ZAPParser().parse(load_fixture("zap.xml"))
    nuclei = NucleiParser().parse(load_fixture("nuclei.jsonl"))
    findings = FindingEngine().analyze(nuclei)

    zap_result = correlate_parsed_bundle("zap", zap["assets"])
    http_like = {
        "type": "url",
        "value": "HTTPS://EXAMPLE.COM:443/",
    }
    http_result = correlate_parsed_bundle(
        "http_fingerprint",
        [http_like],
        existing_assets=zap_result["assets"],
    )
    nuclei_result = correlate_parsed_bundle(
        "nuclei",
        nuclei["assets"],
        findings,
        existing_assets=http_result["assets"],
    )

    urls = [
        asset["value"]
        for asset in nuclei_result["assets"]
        if asset["type"] == "url"
    ]
    internal = [value for value in urls if "internal.test" in value]
    assert set(internal) == {"https://internal.test/"}

    example = [
        asset
        for asset in http_result["assets"]
        if asset["type"] == "url" and asset["value"] == "https://example.com/"
    ]
    assert len(example) == 1


def test_duplicate_asset_prevention_across_scanners():
    dns = DNSParser().parse(load_fixture("dns.jsonl"))
    first = correlate_parsed_bundle("dns", dns["assets"])
    second = correlate_parsed_bundle(
        "subdomain",
        [
            {
                "type": "domain",
                "value": "Internal.TEST.",
            }
        ],
        existing_assets=first["assets"],
    )

    domains = [
        asset
        for asset in second["assets"]
        if asset["type"] == "domain" and asset["value"] == "internal.test"
    ]
    assert len(domains) == 1
    assert domains[0]["metadata"]["sources"] == ["dns", "subdomain"] or (
        "dns" in domains[0]["metadata"]["sources"]
        and "subdomain" in domains[0]["metadata"]["sources"]
    )


def test_duplicate_relationship_prevention():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    first = correlate_parsed_bundle("dns", parsed["assets"])
    combined = correlate_assets(
        {
            "scanner": "dns",
            "assets": first["assets"] + first["assets"],
            "relationships": first["relationships"] + first["relationships"],
        }
    )

    assert len(combined["relationships"]) == len(_rel_set(combined["relationships"]))
    assert len(
        [
            asset
            for asset in combined["assets"]
            if asset["type"] == "domain" and asset["value"] == "internal.test"
        ]
    ) == 1


def test_metadata_source_merging_does_not_duplicate():
    existing = [
        {
            "type": "url",
            "value": "https://internal.test/",
            "metadata": {"sources": ["zap", "nuclei"]},
        }
    ]
    result = correlate_parsed_bundle(
        "nuclei",
        [{"type": "url", "value": "https://INTERNAL.test"}],
        existing_assets=existing,
    )
    urls = [asset for asset in result["assets"] if asset["type"] == "url"]

    assert len(urls) == 1
    assert urls[0]["metadata"]["sources"] == ["zap", "nuclei"]


def test_evidence_only_correlation_does_not_infer_url_to_ip():
    dns = correlate_parsed_bundle(
        "dns",
        DNSParser().parse(load_fixture("dns.jsonl"))["assets"],
    )
    http = correlate_parsed_bundle(
        "http_fingerprint",
        HTTPFingerprintParser().parse(load_fixture("http_fingerprint.json"))["assets"],
        existing_assets=dns["assets"],
    )
    rels = _rel_set(http["relationships"])

    assert not any(
        item[0] == "url" and item[2] == "resolves_to"
        for item in rels
    )
    assert not any(
        item[2] == "resolves_to" and item[1] == "https://internal.test/"
        for item in rels
    )


def test_invalid_observations_are_ignored():
    result = correlate_parsed_bundle(
        "dns",
        [
            {
                "type": "ip",
                "value": "not-an-ip",
                "metadata": {"host": "internal.test", "record": "A"},
            },
            {
                "type": "domain",
                "value": "not a domain",
            },
            {
                "type": "url",
                "value": "javascript:alert(1)",
            },
        ],
    )

    assert result["assets"] == []
    assert result["relationships"] == []
