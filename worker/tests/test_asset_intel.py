from datetime import datetime, timedelta, timezone

from app.asset_intel.enrich import enrich_parsed_output
from app.asset_intel.normalize import (
    canonical_value,
    infer_asset_type,
    infer_asset_value,
    normalize_hostname,
    normalize_ipv4,
    normalize_ipv6,
    normalize_url,
)
from app.finding_engine.engine import FindingEngine
from app.persistence import match_asset_id, merge_metadata, observation_timestamps
from app.scanner.parsers.dns_parser import DNSParser
from app.scanner.parsers.http_fingerprint_parser import HTTPFingerprintParser
from app.scanner.parsers.nikto_parser import NiktoParser
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


def test_domain_case_trailing_dot_and_whitespace_converge():
    assert normalize_hostname("Example.COM.") == "example.com"
    assert normalize_hostname("  example.com  ") == "example.com"
    assert canonical_value("domain", "Example.COM.") == canonical_value(
        "domain",
        "example.com",
    )


def test_url_host_extraction_for_hostname_normalization():
    assert normalize_hostname("https://Example.COM./login") == "example.com"


def test_ipv4_and_ipv6_canonicalization():
    assert normalize_ipv4("  192.0.2.10  ") == "192.0.2.10"
    assert normalize_ipv6("2001:0db8:0000:0000:0000:0000:0000:0008") == "2001:db8::8"
    assert canonical_value("ipv6", "2001:db8:0:0:0:0:0:8") == canonical_value(
        "ipv6",
        "2001:db8::8",
    )


def test_url_normalization_keeps_distinct_paths():
    assert normalize_url("HTTPS://Example.COM./") == "https://example.com/"
    assert normalize_url("https://example.com/api") != normalize_url(
        "https://example.com/login"
    )
    assert "user:secret@" not in normalize_url(
        "https://user:secret@example.com/path"
    )


def test_equivalent_asset_values_converge_for_identity():
    asset_a = {"type": "domain", "value": "Example.COM."}
    asset_b = {"type": "domain", "value": " example.com "}

    assert infer_asset_type(asset_a) == infer_asset_type(asset_b)
    assert infer_asset_value(asset_a) == infer_asset_value(asset_b)


def test_dns_relationships_from_parser_fixture():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    enriched = enrich_parsed_output("dns", parsed["assets"])
    rels = _rel_set(enriched["relationships"])

    assert (
        "domain",
        "internal.test",
        "resolves_to",
        "ip",
        "10.0.0.8",
    ) in rels
    assert (
        "domain",
        "internal.test",
        "resolves_to",
        "ipv6",
        "2001:db8::8",
    ) in rels
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
    assert not any(item[2] == "points_to" and "spf" in item[4] for item in rels)


def test_subdomain_contains_and_nested_parents():
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
    enriched = enrich_parsed_output("subdomain", assets)
    rels = _rel_set(enriched["relationships"])

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


def test_subdomain_fixture_contains_parent_domain():
    parsed = SubdomainParser().parse(load_fixture("subdomain.jsonl"))
    enriched = enrich_parsed_output("subdomain", parsed["assets"])
    rels = _rel_set(enriched["relationships"])

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
        "resolves_to",
        "ip",
        "10.0.0.9",
    ) in rels


def test_nmap_ip_port_service_relationships():
    parsed = NmapParser().parse(load_fixture("nmap.xml"))
    enriched = enrich_parsed_output("nmap", parsed["assets"])
    rels = _rel_set(enriched["relationships"])

    assert ("ip", "10.0.0.8", "exposes", "port", "443") in rels
    assert ("ip", "10.0.0.8", "exposes", "port", "80") in rels
    assert ("port", "443", "runs", "service", "https") in rels
    assert ("port", "80", "runs", "service", "http") in rels


def test_http_fingerprint_url_serves_technology():
    parsed = HTTPFingerprintParser().parse(load_fixture("http_fingerprint.json"))
    enriched = enrich_parsed_output("http_fingerprint", parsed["assets"])
    rels = _rel_set(enriched["relationships"])

    assert (
        "url",
        "https://internal.test/",
        "serves",
        "technology",
        "nginx",
    ) in rels
    assert not any(item[3] == "technology" and item[4] == "text/html" for item in rels)


def test_relationship_extraction_is_deterministic():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    first = enrich_parsed_output("dns", parsed["assets"])["relationships"]
    second = enrich_parsed_output("dns", parsed["assets"])["relationships"]

    assert _rel_set(first) == _rel_set(second)
    assert len(first) == len(_rel_set(first))


def test_provenance_merge_keeps_prior_sources():
    merged = merge_metadata(
        {"sources": ["dns"], "resolver": "10.0.0.53:53"},
        {"sources": ["subdomain"], "resolved_ip": "10.0.0.9"},
        "subdomain",
    )

    assert merged["sources"] == ["dns", "subdomain"]
    assert merged["resolver"] == "10.0.0.53:53"
    assert merged["resolved_ip"] == "10.0.0.9"


def test_first_seen_preserved_last_seen_updates():
    first = datetime(2026, 9, 1, tzinfo=timezone.utc)
    later = first + timedelta(days=1)

    first_seen, last_seen = observation_timestamps(None, first)
    assert first_seen == first
    assert last_seen == first

    first_seen, last_seen = observation_timestamps(first, later)
    assert first_seen == first
    assert last_seen == later


def _associate(scanner: str, parsed: dict) -> str | None:
    findings = FindingEngine().analyze(parsed)
    enriched = enrich_parsed_output(
        scanner,
        parsed.get("assets") or [],
        findings,
    )
    persisted = [
        {
            "id": f"{asset['type']}:{asset['value']}",
            "asset_type": asset["type"],
            "value": asset["value"],
        }
        for asset in enriched["assets"]
    ]
    return match_asset_id(findings[0], persisted, scanner)


def test_finding_association_zap_nikto_nuclei_nmap_tls():
    zap = ZAPParser().parse(load_fixture("zap.xml"))
    nikto = NiktoParser().parse(load_fixture("nikto.json"))
    nuclei = NucleiParser().parse(load_fixture("nuclei.jsonl"))
    nmap = NmapParser().parse(load_fixture("nmap.xml"))
    tls = TLSParser().parse(load_fixture("tls.json"))

    zap_id = _associate("zap", zap)
    nikto_id = _associate("nikto", nikto)
    nuclei_id = _associate("nuclei", nuclei)
    nmap_id = _associate("nmap", nmap)
    tls_id = _associate("tls", tls)

    assert zap_id is not None
    assert nikto_id is not None
    assert nuclei_id == "url:https://internal.test/"
    assert nmap_id in {"port:80", "ip:10.0.0.8"}
    assert tls_id is not None
