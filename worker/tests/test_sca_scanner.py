import json
import tempfile
import os
from pathlib import Path
from app.scanner.scanners.sca import SCAScanner
from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider

def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def test_package_json_discovered():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "package.json"
        _write(p, json.dumps({"dependencies": {"lodash": "4.17.20"}}))
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert data["scanner"] == "sca"
        assert any(d["name"] == "lodash" for d in data["dependencies"])

def test_package_lock_discovered():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "package-lock.json"
        _write(p, json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}))
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert any(d["name"] == "lodash" and d["version"] == "4.17.20" for d in data["dependencies"])

def test_requirements_discovered():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "requirements.txt"
        _write(p, "requests==2.25.0")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert any(d["name"] == "requests" for d in data["dependencies"])

def test_pyproject_discovered():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "pyproject.toml"
        _write(p, "[project]\ndependencies = [\"requests==2.25.0\"]")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert any(d["name"] == "requests" for d in data["dependencies"])

def test_poetry_lock_discovered():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "poetry.lock"
        _write(p, "[[package]]\nname = \"requests\"\nversion = \"2.25.0\"\n")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert any(d["name"] == "requests" for d in data["dependencies"])

def test_ignored_directories_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        _write(base / "package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}}))
        _write(base / "node_modules" / "package.json", json.dumps({"dependencies": {"evil": "1.0.0"}}))
        _write(base / ".git" / "package.json", json.dumps({"dependencies": {"evil2": "1.0.0"}}))
        _write(base / "venv" / "requirements.txt", "evil3==1.0.0")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        names = {d["name"] for d in data["dependencies"]}
        assert "lodash" in names
        assert "evil" not in names
        assert "evil2" not in names
        assert "evil3" not in names

def test_unsupported_manifest_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "Cargo.toml"
        _write(p, "[package]\nname = \"test\"")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert data["dependencies"] == []

def test_empty_project_returns_zero_findings():
    with tempfile.TemporaryDirectory() as tmp:
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert data["dependencies"] == []
        assert data["findings"] == []

def test_malformed_manifest_fails_correctly():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "package.json"
        _write(p, "{invalid json")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert len(data["errors"]) == 1
        assert "Invalid JSON" in data["errors"][0]["error"]

def test_provider_fixture_integration():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "package-lock.json"
        _write(p, json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}))
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["cve"] == "CVE-2021-23337"

def test_provider_osv_integration_mocked():
    from unittest.mock import MagicMock
    from app.services.sca.vuln.osv import OSVVulnerabilityProvider
    from app.services.sca.analyzer import SCAAnalyzer
    import json as js
    mock_client = MagicMock()
    class MockResp:
        status_code = 200
        content = js.dumps({"vulns": [{"id": "GHSA-xxx", "aliases": ["CVE-2021-9999"], "summary": "test"}]}).encode()
        def json(self):
            return {"vulns": [{"id": "GHSA-xxx", "aliases": ["CVE-2021-9999"]}]}
    mock_client.post.return_value = MockResp()
    provider = OSVVulnerabilityProvider(client=mock_client)
    analyzer = SCAAnalyzer(provider=provider)
    # Directly test analyzer with OSV provider
    result = analyzer.analyze({"package-lock.json": js.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})})
    assert len(result["findings"]) == 1

def test_duplicate_manifests_deduplicated():
    with tempfile.TemporaryDirectory() as tmp:
        _write(Path(tmp) / "package.json", json.dumps({"dependencies": {"lodash": "^4.17.20"}}))
        _write(Path(tmp) / "package-lock.json", json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}}}))
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        lodash = [d for d in data["dependencies"] if d["name"] == "lodash"]
        assert len(lodash) == 1
        assert lodash[0]["version"] == "4.17.21"

def test_max_manifest_limit_enforced():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        for i in range(12):
            sub = base / f"proj{i}"
            _write(sub / "package.json", json.dumps({"dependencies": {f"pkg{i}": "1.0.0"}}))
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert len(data["dependencies"]) <= 10

def test_dependency_count_correct():
    with tempfile.TemporaryDirectory() as tmp:
        _write(Path(tmp) / "package.json", json.dumps({"dependencies": {"a": "1.0.0", "b": "2.0.0"}}))
        _write(Path(tmp) / "requirements.txt", "requests==2.25.0")
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert data["metadata"]["dependencies_total"] == 3

def test_findings_generated():
    with tempfile.TemporaryDirectory() as tmp:
        _write(Path(tmp) / "package-lock.json", json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}))
        scanner = SCAScanner()
        raw = scanner.scan(tmp)
        data = json.loads(raw)
        assert len(data["findings"]) > 0
        assert data["findings"][0]["scanner"] == "sca"
