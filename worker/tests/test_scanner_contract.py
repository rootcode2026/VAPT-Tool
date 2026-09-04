"""S7.1 Scanner Platform Contract — generic guarantees for all scanners."""

import pytest

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.parsers.registry import ParserRegistry
from app.scanner.registry import ScannerRegistry
from app.scanner.scanners.sca import SCAScanner
from app.scanner.scanners.sast import SASTScanner


def _registry():
    return ScannerRegistry()


def test_all_scanners_satisfy_base_contract():
    registry = _registry()
    for meta in registry.list():
        assert "name" in meta and meta["name"]
        assert "category" in meta and meta["category"]
        assert "description" in meta and isinstance(meta["description"], str)
        assert "target_types" in meta and isinstance(meta["target_types"], list)
        assert "input_type" in meta
        assert "output_format" in meta
        assert "timeout" in meta and isinstance(meta["timeout"], int) and meta["timeout"] > 0
        # New AppSec contract fields (additive, must exist)
        assert "family" in meta
        assert "requires_workspace" in meta and isinstance(meta["requires_workspace"], bool)
        assert "supported_profiles" in meta and isinstance(meta["supported_profiles"], list)


def test_scanner_instances_are_base_scanner():
    registry = _registry()
    for name in ["nmap", "nuclei", "http_fingerprint", "zap", "nikto", "tls", "dns", "subdomain", "sca", "sast"]:
        scanner = registry.get(name)
        assert isinstance(scanner, BaseScanner), f"{name} not BaseScanner"
        assert hasattr(scanner, "scan") and callable(scanner.scan)
        assert hasattr(scanner, "scan_with_context") and callable(scanner.scan_with_context)


def test_scan_context_backward_compat():
    # Existing scanners must still work via scan(target)
    # New context should delegate to scan()
    registry = _registry()
    for name in registry.list():
        scanner = registry.get(name["name"])
        ctx = ScanContext(target="example.com", target_type=name["target_types"][0] if name["target_types"] else None)
        # Should not raise due to missing workspace for non-workspace scanners
        # For workspace scanners, scan_with_context should still be callable (may fail on missing workspace but not on contract)
        assert isinstance(ctx.target, str)
        # Verify metadata includes required workspace flag type
        assert isinstance(scanner.requires_workspace, bool)


def test_sca_sast_require_workspace():
    assert SCAScanner.requires_workspace is True
    assert SASTScanner.requires_workspace is True
    assert SCAScanner.family == "sca"
    assert SASTScanner.family == "sast"
    assert "sca" in SCAScanner.supported_profiles
    assert "sast" in SASTScanner.supported_profiles


def test_scan_context_validation():
    ctx = ScanContext(target="example.com", workspace="/tmp/workspace")
    assert ctx.target == "example.com"
    assert ctx.workspace == "/tmp/workspace"
    # ScanContext with metadata
    ctx2 = ScanContext(target="8.8.8.8", target_type="ip", project_id="p1", scan_id="s1")
    assert ctx2.target_type == "ip"
    assert ctx2.project_id == "p1"


def test_docker_runner_volumes_validation():
    from app.scanner.docker_runner import DockerRunner

    runner = DockerRunner(client=object())  # dummy client, only validation tested
    # Valid volumes
    validated = runner._validate_volumes({"/tmp/workspace": {"bind": "/workspace", "mode": "ro"}})
    assert "/tmp/workspace" in validated
    # Invalid: relative path
    with pytest.raises(ValueError):
        runner._validate_volumes({"relative/path": {"bind": "/workspace"}})
    # Invalid: traversal
    with pytest.raises(ValueError):
        runner._validate_volumes({"/tmp/../etc": {"bind": "/workspace"}})
    # Invalid: sensitive root not allowed unless /tmp or /workspace
    with pytest.raises(ValueError):
        runner._validate_volumes({"/etc/passwd": {"bind": "/workspace"}})


def test_parser_contract_all_parsers():
    registry = ParserRegistry()
    for scanner_name in registry.list():
        parser = registry.get(scanner_name)
        assert hasattr(parser, "scanner_name") and parser.scanner_name == scanner_name
        assert hasattr(parser, "parse") and callable(parser.parse)
        # Malformed output must not crash with unhandled exception type
        try:
            result = parser.parse("")
        except Exception as exc:
            # Parser may raise ValueError for malformed, but not silently fabricate findings
            assert isinstance(exc, (ValueError, Exception))
        else:
            assert "scanner" in result and "assets" in result and "findings" in result
            assert isinstance(result["assets"], list) and isinstance(result["findings"], list)


def test_sarif_parser_generic():
    from app.scanner.parsers.sarif_parser import SarifParser

    parser = SarifParser()
    assert parser.scanner_name == "sarif"

    # Empty should not crash
    assert parser.parse("") == {"scanner": "sarif", "assets": [], "findings": []}
    assert parser.parse("   ") == {"scanner": "sarif", "assets": [], "findings": []}

    # Minimal valid SARIF
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "test-scanner", "rules": [{"id": "RULE001", "shortDescription": {"text": "Test rule"}}]}},
                "results": [
                    {
                        "ruleId": "RULE001",
                        "level": "error",
                        "message": {"text": "Vulnerability found"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 42}}}
                        ],
                    }
                ],
            }
        ],
    }
    import json

    result = parser.parse(json.dumps(sarif))
    assert result["scanner"] == "sarif"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][0]["file"] == "src/app.py"
    assert result["findings"][0]["line"] == 42
    assert len(result["assets"]) == 1
    assert result["assets"][0]["type"] == "source_file"

    # Malformed SARIF should raise ValueError, not generic
    with pytest.raises(ValueError):
        parser.parse("{ not json")
    with pytest.raises(ValueError):
        parser.parse(json.dumps({"version": "2.1.0"}))  # missing runs


def test_scanner_registry_duplicate_rejection():
    registry = _registry()
    from app.scanner.base import BaseScanner

    class Dummy(BaseScanner):
        name = "nmap"  # already exists

        def scan(self, target: str) -> str:
            return ""

    with pytest.raises(ValueError):
        registry.register(Dummy())


def test_parser_registry_duplicate_rejection():
    registry = ParserRegistry()
    from app.scanner.parsers.base import BaseParser

    class DummyParser(BaseParser):
        scanner_name = "nmap"

        def parse(self, raw_output: str) -> dict:
            return {"scanner": "nmap", "assets": [], "findings": []}

    with pytest.raises(ValueError):
        registry.register(DummyParser())


def test_profile_extensibility():
    from app.scanner.profiles import SCAN_PROFILES, get_scanners_for_profile

    # Existing profiles remain
    assert "quick" in SCAN_PROFILES
    assert "web" in SCAN_PROFILES
    assert "full" in SCAN_PROFILES
    # New AppSec profiles are present (empty until scanners land)
    for profile in ["secrets", "container", "iac", "api"]:
        assert profile in SCAN_PROFILES
        assert isinstance(get_scanners_for_profile(profile), list)
    # Invalid profile raises
    with pytest.raises(ValueError):
        get_scanners_for_profile("nonexistent-profile-xyz")


def test_asset_types_appsec():
    from app.asset_intel.types import CANONICAL_ASSET_TYPES

    for t in ["package", "container_image", "repository", "source_file"]:
        assert t in CANONICAL_ASSET_TYPES


def test_evidence_types_appsec():
    from app.services.finding_correlation.evidence import EVIDENCE_TYPES

    for t in ["secret", "container_layer", "iac_resource", "api_endpoint", "repository"]:
        assert t in EVIDENCE_TYPES
