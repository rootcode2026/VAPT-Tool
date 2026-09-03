import pytest

from app.asset_intel.correlate import correlate_assets, correlate_parsed_bundle
from app.asset_intel.provenance import (
    RELATIONSHIP_SEMANTICS,
    RelationshipValidationError,
    merge_relationship_metadata,
    validate_relationship,
)
from app.asset_intel.types import RELATIONSHIP_TYPES
from app.scanner.parsers.dns_parser import DNSParser
from app.scanner.parsers.http_fingerprint_parser import HTTPFingerprintParser
from app.scanner.parsers.nmap_parser import NmapParser
from app.scanner.parsers.tls_parser import TLSParser

from tests.helpers import load_fixture


def _find_rel(relationships, rel_type, source_value=None, target_value=None):
    matches = []
    for item in relationships:
        if item["relationship_type"] != rel_type:
            continue
        if source_value and item["source_value"] != source_value:
            continue
        if target_value and item["target_value"] != target_value:
            continue
        matches.append(item)
    return matches


def test_dns_relationship_preserves_source_and_a_record_evidence():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    result = correlate_parsed_bundle("dns", parsed["assets"])
    rel = _find_rel(
        result["relationships"],
        "resolves_to",
        "internal.test",
        "10.0.0.8",
    )[0]

    assert rel["metadata"]["sources"] == ["dns"]
    assert rel["metadata"]["confidence"] == "high"
    assert rel["metadata"]["evidence"]["record_type"] == "A"
    assert rel["metadata"]["evidence"]["observed_value"] == "10.0.0.8"


def test_nmap_and_http_relationship_evidence():
    nmap = correlate_parsed_bundle(
        "nmap",
        NmapParser().parse(load_fixture("nmap.xml"))["assets"],
    )
    http = correlate_parsed_bundle(
        "http_fingerprint",
        HTTPFingerprintParser().parse(load_fixture("http_fingerprint.json"))["assets"],
    )
    tls = correlate_parsed_bundle(
        "tls",
        TLSParser().parse(load_fixture("tls.json"))["assets"],
    )

    exposes = _find_rel(nmap["relationships"], "exposes", "10.0.0.8", "443")[0]
    assert exposes["metadata"]["sources"] == ["nmap"]
    assert exposes["metadata"]["evidence"]["protocol"] == "tcp"
    assert exposes["metadata"]["confidence"] == "high"

    serves = _find_rel(http["relationships"], "serves", "https://internal.test/")[0]
    assert serves["metadata"]["sources"] == ["http_fingerprint"]
    assert serves["metadata"]["evidence"]["observed_value"] == "nginx"

    uses = _find_rel(tls["relationships"], "uses", target_value="internal.test:443")[0]
    assert uses["metadata"]["sources"] == ["tls"]
    assert uses["metadata"]["confidence"] == "high"


def test_relationship_metadata_merge_retains_sources_and_evidence():
    merged = merge_relationship_metadata(
        {
            "sources": ["dns"],
            "confidence": "high",
            "evidence": {"record_type": "A", "observed_value": "10.0.0.8"},
        },
        {
            "sources": ["subdomain"],
            "evidence": {"kind": "resolved_ip"},
        },
        "subdomain",
    )

    assert merged["sources"] == ["dns", "subdomain"]
    assert merged["evidence"]["record_type"] == "A"
    assert merged["evidence"]["observed_value"] == "10.0.0.8"
    assert merged["evidence"]["kind"] == "resolved_ip"
    assert merged["confidence"] == "high"


def test_duplicate_relationship_in_one_bundle_merges_sources():
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    first = correlate_parsed_bundle("dns", parsed["assets"])
    combined = correlate_assets(
        {
            "scanner": "nmap",
            "assets": first["assets"],
            "relationships": first["relationships"]
            + [
                {
                    "source_type": "domain",
                    "source_value": "internal.test",
                    "target_type": "ip",
                    "target_value": "10.0.0.8",
                    "relationship_type": "resolves_to",
                    "metadata": {"record": "A"},
                }
            ],
        }
    )

    matches = _find_rel(
        combined["relationships"],
        "resolves_to",
        "internal.test",
        "10.0.0.8",
    )
    assert len(matches) == 1
    assert matches[0]["metadata"]["sources"] == ["dns", "nmap"]


def test_relationship_semantics_cover_current_types():
    assert set(RELATIONSHIP_SEMANTICS) == RELATIONSHIP_TYPES
    parsed = DNSParser().parse(load_fixture("dns.jsonl"))
    dns = correlate_parsed_bundle("dns", parsed["assets"])
    nmap = correlate_parsed_bundle(
        "nmap",
        NmapParser().parse(load_fixture("nmap.xml"))["assets"],
    )
    http = correlate_parsed_bundle(
        "http_fingerprint",
        HTTPFingerprintParser().parse(load_fixture("http_fingerprint.json"))["assets"],
    )
    tls = correlate_parsed_bundle(
        "tls",
        TLSParser().parse(load_fixture("tls.json"))["assets"],
    )

    types_seen = {
        item["relationship_type"]
        for item in (
            dns["relationships"]
            + nmap["relationships"]
            + http["relationships"]
            + tls["relationships"]
        )
    }
    for expected in (
        "contains",
        "resolves_to",
        "points_to",
        "exposes",
        "runs",
        "serves",
        "uses",
        "observed_on",
    ):
        assert expected in types_seen or expected in RELATIONSHIP_SEMANTICS


def test_relationship_validation_rejects_invalid_cases():
    source = {"id": "a1", "project_id": "p1"}
    target = {"id": "a2", "project_id": "p1"}

    with pytest.raises(RelationshipValidationError, match="Unsupported"):
        validate_relationship(
            project_id="p1",
            relationship_type="owns",
            source_asset=source,
            target_asset=target,
        )
    with pytest.raises(RelationshipValidationError, match="Source asset"):
        validate_relationship(
            project_id="p1",
            relationship_type="resolves_to",
            source_asset=None,
            target_asset=target,
        )
    with pytest.raises(RelationshipValidationError, match="Target asset"):
        validate_relationship(
            project_id="p1",
            relationship_type="resolves_to",
            source_asset=source,
            target_asset=None,
        )
    with pytest.raises(RelationshipValidationError, match="same asset"):
        validate_relationship(
            project_id="p1",
            relationship_type="resolves_to",
            source_asset=source,
            target_asset=source,
        )
    with pytest.raises(RelationshipValidationError, match="Source asset does not"):
        validate_relationship(
            project_id="p1",
            relationship_type="resolves_to",
            source_asset={"id": "a1", "project_id": "other"},
            target_asset=target,
        )
    with pytest.raises(RelationshipValidationError, match="JSON"):
        validate_relationship(
            project_id="p1",
            relationship_type="resolves_to",
            source_asset=source,
            target_asset=target,
            metadata={"bad": object()},
        )
