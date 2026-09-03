import os
import pytest
from unittest.mock import MagicMock, patch
from app.services.sca.factory import get_vulnerability_provider, create_sca_analyzer
from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider
from app.services.sca.vuln.osv import OSVVulnerabilityProvider, OSVProviderError
from app.services.sca.analyzer import SCAAnalyzer

def test_provider_factory_selects_fixture(monkeypatch):
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "fixture")
    provider = get_vulnerability_provider()
    assert isinstance(provider, FixtureVulnerabilityProvider)

def test_provider_factory_selects_osv(monkeypatch):
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "osv")
    provider = get_vulnerability_provider()
    assert isinstance(provider, OSVVulnerabilityProvider)

def test_unknown_provider_fails_clearly(monkeypatch):
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "unknown_xyz")
    try:
        get_vulnerability_provider()
        assert False, "should raise"
    except ValueError as e:
        assert "Unknown" in str(e)
        assert "osv" in str(e).lower() or "fixture" in str(e).lower()

def test_production_default_selects_osv(monkeypatch):
    monkeypatch.delenv("SCA_VULNERABILITY_PROVIDER", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    # Need to reload settings? Factory checks os.getenv, so it will see production
    provider = get_vulnerability_provider()
    assert isinstance(provider, OSVVulnerabilityProvider)

def test_fixture_provider_deterministic():
    provider = FixtureVulnerabilityProvider()
    from app.services.sca.models import Dependency
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    assert provider.lookup(dep) == provider.lookup(dep)

def test_explicit_fixture_injection_works():
    provider = FixtureVulnerabilityProvider()
    analyzer = SCAAnalyzer(provider=provider)
    result = analyzer.analyze({"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'})
    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve"] == "CVE-2021-23337"

def test_explicit_osv_injection_works():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    class MockResp:
        status_code = 200
        content = b'{"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2021-0001"]}]}'
        def json(self):
            return {"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2021-0001"]}]}
    mock_client.post.return_value = MockResp()
    provider._client = mock_client
    analyzer = SCAAnalyzer(provider=provider)
    result = analyzer.analyze({"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'})
    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve"] == "CVE-2021-0001"

def test_sca_scanner_uses_configured_provider(monkeypatch):
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "fixture")
    # SCAScanner should use factory which will be fixture
    from app.services.sca.factory import get_vulnerability_provider
    provider = get_vulnerability_provider()
    assert isinstance(provider, FixtureVulnerabilityProvider)
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "osv")
    provider2 = get_vulnerability_provider()
    assert isinstance(provider2, OSVVulnerabilityProvider)

def test_normal_test_suite_no_network(monkeypatch):
    # Default without env should be fixture in test env (ENVIRONMENT != production)
    monkeypatch.delenv("SCA_VULNERABILITY_PROVIDER", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    provider = get_vulnerability_provider()
    assert isinstance(provider, FixtureVulnerabilityProvider)
    # Ensure fixture lookup doesn't need network
    from app.services.sca.models import Dependency
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    assert len(provider.lookup(dep)) == 1

def test_osv_provider_errors_remain_provider_errors():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.side_effect = Exception("connection failed")
    provider._client = mock_client
    from app.services.sca.models import Dependency
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    try:
        provider.lookup(dep)
        assert False
    except OSVProviderError:
        pass

def test_no_silent_fallback_from_osv_to_fixture(monkeypatch):
    # Configure for osv, make OSV fail, ensure analyzer reports provider_error not clean
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "osv")
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.side_effect = Exception("OSV down")
    provider._client = mock_client
    analyzer = SCAAnalyzer(provider=provider)
    with patch.object(provider, "lookup", side_effect=OSVProviderError("OSV down")):
        result = analyzer.analyze({"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'})
        assert any(e.get("provider_error") for e in result["errors"])
        assert len(result["findings"]) == 0
        # Ensure not silently using fixture (which would have found vuln)
        assert not any("CVE-2021-23337" in str(f) for f in result["findings"])

def test_environment_value_normalization(monkeypatch):
    for val in ["OSV", "Osv", "osv", "OSV ", " osv"]:
        monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", val)
        provider = get_vulnerability_provider()
        assert isinstance(provider, OSVVulnerabilityProvider)
    for val in ["FIXTURE", "Fixture", "fixture"]:
        monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", val)
        provider = get_vulnerability_provider()
        assert isinstance(provider, FixtureVulnerabilityProvider)

def test_missing_provider_configuration_behavior(monkeypatch):
    monkeypatch.delenv("SCA_VULNERABILITY_PROVIDER", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    # Should default to fixture, not error
    provider = get_vulnerability_provider()
    assert isinstance(provider, FixtureVulnerabilityProvider)
    monkeypatch.setenv("ENVIRONMENT", "production")
    provider2 = get_vulnerability_provider()
    assert isinstance(provider2, OSVVulnerabilityProvider)

def test_scanner_execution_with_fixture_provider(monkeypatch):
    # Simulate SCAScanner using fixture
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "fixture")
    from app.services.sca.factory import create_sca_analyzer
    analyzer = create_sca_analyzer()
    assert isinstance(analyzer.provider, FixtureVulnerabilityProvider)
    result = analyzer.analyze({"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'})
    assert len(result["findings"]) == 1

def test_scanner_execution_with_mocked_osv_provider(monkeypatch):
    monkeypatch.setenv("SCA_VULNERABILITY_PROVIDER", "osv")
    from app.services.sca.factory import create_sca_analyzer
    # Mock OSV client to avoid network
    mock_client = MagicMock()
    class MockResp:
        status_code = 200
        content = b'{"vulns": [{"id": "GHSA-mocked", "aliases": ["CVE-2021-9999"]}]}'
        def json(self):
            return {"vulns": [{"id": "GHSA-mocked", "aliases": ["CVE-2021-9999"]}]}
    mock_client.post.return_value = MockResp()
    # Need to inject mock client into provider created by factory
    # Factory creates new OSV provider; we can patch its _client after
    analyzer = create_sca_analyzer()
    # Ensure it's OSV
    assert isinstance(analyzer.provider, OSVVulnerabilityProvider)
    analyzer.provider._client = mock_client
    result = analyzer.analyze({"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'})
    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve"] == "CVE-2021-9999"
