import json
import pytest
from unittest.mock import MagicMock, patch
from app.services.sca.models import Dependency
from app.services.sca.vuln.osv import OSVVulnerabilityProvider, OSVProviderError
from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider
from app.services.sca.analyzer import SCAAnalyzer

def _dep(ecosystem, name, version, resolved=True):
    return Dependency(ecosystem=ecosystem, name=name, version=version, manifest="package-lock.json" if ecosystem=="npm" else "requirements.txt", dependency_type="runtime", version_resolved=resolved)

# Helper mock response
class MockResponse:
    def __init__(self, status_code, json_data=None, content=None):
        self.status_code = status_code
        self._json_data = json_data
        if content is not None:
            self.content = content
        elif json_data is not None:
            self.content = json.dumps(json_data).encode()
        else:
            self.content = b""
    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.content)

def test_npm_lookup():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-xxx", "summary": "x", "aliases": ["CVE-2021-23337"], "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}]})
    provider._client = mock_client
    dep = _dep("npm", "lodash", "4.17.20")
    vulns = provider.lookup(dep)
    assert len(vulns) == 1
    # Verify request payload ecosystem mapping npm->npm
    args, kwargs = mock_client.post.call_args
    assert kwargs["json"]["package"]["ecosystem"] == "npm"
    assert kwargs["json"]["package"]["name"] == "lodash"

def test_pypi_lookup():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": []})
    provider._client = mock_client
    dep = _dep("pypi", "requests", "2.25.0")
    vulns = provider.lookup(dep)
    assert vulns == []
    args, kwargs = mock_client.post.call_args
    assert kwargs["json"]["package"]["ecosystem"] == "PyPI"

def test_exact_version_lookup():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-1", "aliases": ["CVE-2021-0001"]}]})
    provider._client = mock_client
    dep = _dep("npm", "lodash", "4.17.20")
    assert len(provider.lookup(dep)) == 1
    # Wrong version would be different dep, but provider would still query OSV and OSV would return empty if not vulnerable
    # For exact version test, we mock empty for wrong version
    mock_client.post.return_value = MockResponse(200, {"vulns": []})
    dep2 = _dep("npm", "lodash", "4.17.21")
    assert len(provider.lookup(dep2)) == 0

def test_unresolved_skips_lookup():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    provider._client = mock_client
    dep = _dep("npm", "lodash", "^4.17.20", resolved=False)
    assert provider.lookup(dep) == []
    mock_client.post.assert_not_called()
    dep2 = _dep("pypi", "requests", None, resolved=False)
    assert provider.lookup(dep2) == []

def test_successful_empty_response():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": []})
    provider._client = mock_client
    dep = _dep("npm", "express", "4.18.0")
    assert provider.lookup(dep) == []

def test_one_vulnerability():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-aaa", "summary": "test", "aliases": ["CVE-2021-23337"]}]})
    provider._client = mock_client
    vulns = provider.lookup(_dep("npm", "lodash", "4.17.20"))
    assert len(vulns) == 1
    assert vulns[0].vulnerability_id == "GHSA-aaa"
    assert vulns[0].source == "osv"

def test_multiple_vulnerabilities():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}, {"id": "CVE-2021-0001"}]})
    provider._client = mock_client
    vulns = provider.lookup(_dep("npm", "lodash", "4.17.20"))
    assert len(vulns) == 3
    ids = {v.vulnerability_id for v in vulns}
    assert ids == {"GHSA-1", "GHSA-2", "CVE-2021-0001"}

def test_cve_alias_extraction():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-4xc9", "aliases": ["CVE-2021-23337", "GHSA-xxx"]}]})
    provider._client = mock_client
    vuln = provider.lookup(_dep("npm", "lodash", "4.17.20"))[0]
    assert vuln.metadata.get("cve_alias") == "CVE-2021-23337"
    assert vuln.vulnerability_id == "GHSA-4xc9"

def test_osv_id_preservation():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-4xc9-xhrj-v574", "aliases": ["CVE-2021-23337"]}]})
    provider._client = mock_client
    vuln = provider.lookup(_dep("npm", "lodash", "4.17.20"))[0]
    assert vuln.vulnerability_id == "GHSA-4xc9-xhrj-v574"
    assert vuln.metadata["osv_id"] == "GHSA-4xc9-xhrj-v574"

def test_severity_normalization():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-1", "database_specific": {"severity": "critical"}}]})
    provider._client = mock_client
    assert provider.lookup(_dep("npm", "lodash", "4.17.20"))[0].severity == "critical"
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-2", "database_specific": {"severity": "high"}}]})
    assert provider.lookup(_dep("npm", "lodash", "4.17.20"))[0].severity == "high"

def test_score_extraction():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-1", "severity": [{"type": "CVSS_V3", "score": 7.5}], "database_specific": {"cvss": 7.5}}]})
    provider._client = mock_client
    assert provider.lookup(_dep("npm", "lodash", "4.17.20"))[0].score == 7.5

def test_fixed_version_extraction():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-1", "database_specific": {"fixed_version": "4.17.21"}}]})
    provider._client = mock_client
    assert provider.lookup(_dep("npm", "lodash", "4.17.20"))[0].fixed_version == "4.17.21"
    # No fixed -> None
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-2"}]})
    assert provider.lookup(_dep("npm", "lodash", "4.17.20"))[0].fixed_version is None

def test_duplicate_suppression():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-dup"}, {"id": "GHSA-dup"}]})
    provider._client = mock_client
    vulns = provider.lookup(_dep("npm", "lodash", "4.17.20"))
    assert len(vulns) == 1

def test_http_404():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(404, {})
    provider._client = mock_client
    assert provider.lookup(_dep("npm", "lodash", "4.17.20")) == []

def test_http_429_retry():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    # First 429, then success
    mock_client.post.side_effect = [MockResponse(429, {}), MockResponse(200, {"vulns": [{"id": "GHSA-1"}]})]
    provider._client = mock_client
    vulns = provider.lookup(_dep("npm", "lodash", "4.17.20"))
    assert len(vulns) == 1
    assert mock_client.post.call_count == 2

def test_http_429_persistent_failure():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.side_effect = [MockResponse(429, {}), MockResponse(429, {})]
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False, "should raise"
    except OSVProviderError as e:
        assert "429" in str(e)

def test_http_500():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(500, {})
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False
    except OSVProviderError as e:
        assert "500" in str(e)

def test_timeout():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    def raise_timeout(*a, **kw):
        raise TimeoutError("timed out")
    mock_client.post.side_effect = raise_timeout
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False
    except OSVProviderError as e:
        assert "timeout" in str(e).lower()

def test_connection_error():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    def raise_conn(*a, **kw):
        raise ConnectionError("DNS failure")
    mock_client.post.side_effect = raise_conn
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False
    except OSVProviderError as e:
        assert "connection" in str(e).lower() or "dns" in str(e).lower()

def test_malformed_json():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, content=b"not json", json_data=None)
    # Make json() raise
    mock_client.post.return_value.json = MagicMock(side_effect=json.JSONDecodeError("msg", "doc", 0))
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False
    except OSVProviderError as e:
        assert "JSON" in str(e)

def test_malformed_osv_response():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": "not a list"})
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False
    except OSVProviderError:
        pass

def test_no_false_vulnerability_on_provider_failure():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.side_effect = Exception("connection failed")
    provider._client = mock_client
    try:
        provider.lookup(_dep("npm", "lodash", "4.17.20"))
        assert False
    except OSVProviderError:
        pass
    # Analyzer should not treat this as clean
    analyzer = SCAAnalyzer(provider=provider)
    # Mock provider to raise for this dep
    with patch.object(provider, "lookup", side_effect=OSVProviderError("fail")):
        result = analyzer.analyze({"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'})
        # Should have provider error, not clean findings
        assert any(e.get("provider_error") for e in result["errors"])
        assert len(result["findings"]) == 0

def test_provider_selection():
    fixture = FixtureVulnerabilityProvider()
    osv = OSVVulnerabilityProvider()
    # Mock OSV to return one vuln
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-osv", "aliases": ["CVE-2021-0001"]}]})
    osv._client = mock_client
    analyzer_fixture = SCAAnalyzer(provider=fixture)
    analyzer_osv = SCAAnalyzer(provider=osv)
    manifests = {"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'}
    r_fixture = analyzer_fixture.analyze(manifests)
    r_osv = analyzer_osv.analyze(manifests)
    assert r_fixture["findings"][0]["cve"] == "CVE-2021-23337"
    assert r_osv["findings"][0]["cve"] == "CVE-2021-0001"
    assert r_osv["findings"][0]["metadata"]["vulnerability_id"] == "GHSA-osv"

def test_fixture_provider_still_works():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    assert len(provider.lookup(dep)) == 1

def test_sca_analyzer_with_mocked_osv():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-mocked", "summary": "mocked vuln", "aliases": ["CVE-2021-9999"], "database_specific": {"fixed_version": "4.17.22"}}]})
    provider._client = mock_client
    analyzer = SCAAnalyzer(provider=provider)
    manifests = {"package-lock.json": '{"lockfileVersion":2,"packages":{"": {}, "node_modules/lodash":{"version":"4.17.20"}}}'}
    result = analyzer.analyze(manifests)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve"] == "CVE-2021-9999"
    assert "4.17.22" in result["findings"][0]["remediation"]

def test_deterministic_normalized_result():
    provider = OSVVulnerabilityProvider()
    mock_client = MagicMock()
    mock_client.post.return_value = MockResponse(200, {"vulns": [{"id": "GHSA-1", "summary": "s", "aliases": ["CVE-1"]}]})
    provider._client = mock_client
    dep = _dep("npm", "lodash", "4.17.20")
    v1 = provider.lookup(dep)
    v2 = provider.lookup(dep)
    assert v1 == v2

def test_no_network_dependency_in_unit_tests():
    # Ensure fixture provider doesn't need network
    provider = FixtureVulnerabilityProvider()
    dep = _dep("npm", "lodash", "4.17.20")
    # Should work without mock
    vulns = provider.lookup(dep)
    assert len(vulns) == 1
