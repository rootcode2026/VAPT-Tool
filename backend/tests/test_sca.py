import json
import pytest
from app.services.sca.parsers.package_json import PackageJsonParser
from app.services.sca.parsers.package_lock import PackageLockParser
from app.services.sca.parsers.requirements import RequirementsParser
from app.services.sca.parsers.pyproject import PyprojectParser
from app.services.sca.parsers.poetry_lock import PoetryLockParser
from app.services.sca.parsers.registry import SCARegistry
from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider
from app.services.sca.analyzer import SCAAnalyzer
from app.services.sca.models import Dependency

# Manifest parsing tests
def test_package_json_dependencies():
    content = json.dumps({"dependencies": {"lodash": "^4.17.20", "express": "^4.18.0"}})
    deps = PackageJsonParser().parse(content)
    assert len(deps) == 2
    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.version == "^4.17.20"
    assert lodash.dependency_type == "runtime"
    assert lodash.ecosystem == "npm"

def test_package_json_dev_dependencies():
    content = json.dumps({"devDependencies": {"jest": "^29.0.0"}})
    deps = PackageJsonParser().parse(content)
    assert len(deps) == 1
    assert deps[0].dependency_type == "development"
    assert deps[0].name == "jest"

def test_package_json_optional_dependencies():
    content = json.dumps({"optionalDependencies": {"fsevents": "^2.3.0"}})
    deps = PackageJsonParser().parse(content)
    assert deps[0].dependency_type == "optional"

def test_package_lock_exact_versions():
    content = json.dumps({
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "test"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.18.0"},
        }
    })
    deps = PackageLockParser().parse(content)
    assert len(deps) == 2
    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.version == "4.17.20"
    assert lodash.version_resolved is True

def test_requirements_pinned():
    content = "requests==2.25.0\nurllib3==1.26.4"
    deps = RequirementsParser().parse(content)
    assert len(deps) == 2
    req = next(d for d in deps if d.name == "requests")
    assert req.version == "2.25.0"
    assert req.version_resolved is True

def test_requirements_unpinned():
    content = "requests"
    deps = RequirementsParser().parse(content)
    assert deps[0].version is None
    assert deps[0].version_resolved is False

def test_requirements_version_ranges():
    content = "requests>=2.25.0\nurllib3~=1.26.0"
    deps = RequirementsParser().parse(content)
    req = next(d for d in deps if d.name == "requests")
    assert req.version == ">=2.25.0"
    assert req.version_resolved is False

def test_pyproject_dependencies():
    content = """
[project]
dependencies = ["requests==2.25.0", "urllib3>=1.26.4"]
"""
    deps = PyprojectParser().parse(content)
    assert len(deps) == 2
    req = next(d for d in deps if d.name == "requests")
    assert req.version == "2.25.0"
    assert req.version_resolved is True

def test_poetry_lock():
    content = """
[[package]]
name = "requests"
version = "2.25.0"

[[package]]
name = "urllib3"
version = "1.26.4"
"""
    deps = PoetryLockParser().parse(content)
    assert len(deps) == 2
    assert any(d.name == "requests" and d.version == "2.25.0" for d in deps)

def test_malformed_json():
    with pytest.raises(ValueError, match="Invalid JSON"):
        PackageJsonParser().parse("{invalid json}")

def test_malformed_toml():
    with pytest.raises(ValueError, match="Invalid TOML"):
        PyprojectParser().parse("[[project\n dependencies = [")

def test_malformed_requirements():
    # Empty name should raise
    with pytest.raises(ValueError):
        RequirementsParser().parse("==2.25.0")

def test_unsupported_manifest_structure():
    content = json.dumps({"lockfileVersion": 2})  # missing packages/dependencies but valid empty?
    # PackageLockParser should return [] or raise? For empty lockfile with no packages, return []
    deps = PackageLockParser().parse(content)
    assert deps == []

# Normalization tests
def test_npm_normalization():
    content = json.dumps({"dependencies": {"Lodash": "^4.17.20"}})
    deps = PackageJsonParser().parse(content)
    # Name is sanitized but case preserved? Our parser preserves original but identity is lower
    assert deps[0].name == "Lodash"
    assert deps[0].ecosystem == "npm"

def test_pypi_normalization():
    deps = RequirementsParser().parse("Requests==2.25.0")
    assert deps[0].ecosystem == "pypi"
    assert deps[0].name == "Requests"

def test_duplicate_dependencies():
    analyzer = SCAAnalyzer()
    manifests = {
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.20"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}),
    }
    result = analyzer.analyze(manifests)
    # Should deduplicate to one lodash
    lodash_deps = [d for d in result["dependencies"] if d["name"].lower() == "lodash"]
    assert len(lodash_deps) == 1

def test_lockfile_overrides_manifest_range():
    analyzer = SCAAnalyzer()
    manifests = {
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.20"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}}}),
    }
    result = analyzer.analyze(manifests)
    lodash = next(d for d in result["dependencies"] if d["name"].lower() == "lodash")
    assert lodash["version"] == "4.17.21"
    assert lodash["version_resolved"] is True

def test_unresolved_version_remains_unresolved():
    deps = RequirementsParser().parse("requests")
    assert deps[0].version is None
    assert deps[0].version_resolved is False

def test_multiple_manifests():
    analyzer = SCAAnalyzer()
    manifests = {
        "requirements.txt": "requests==2.25.0",
        "pyproject.toml": "[project]\ndependencies = [\"urllib3==1.26.4\"]",
    }
    result = analyzer.analyze(manifests)
    assert len(result["dependencies"]) == 2

# Vulnerability matching tests
def test_exact_package_match():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    vulns = provider.lookup(dep)
    assert len(vulns) == 1
    assert vulns[0].vulnerability_id == "CVE-2021-23337"

def test_exact_version_match():
    provider = FixtureVulnerabilityProvider()
    dep_good = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    dep_bad = Dependency(ecosystem="npm", name="lodash", version="4.17.21", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    assert len(provider.lookup(dep_good)) == 1
    assert len(provider.lookup(dep_bad)) == 0

def test_wrong_version_no_match():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.19", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    assert provider.lookup(dep) == []

def test_wrong_ecosystem_no_match():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="pypi", name="lodash", version="4.17.20", manifest="requirements.txt", dependency_type="runtime", version_resolved=True)
    assert provider.lookup(dep) == []

def test_unresolved_version_no_false_vulnerability():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="npm", name="lodash", version="^4.17.20", manifest="package.json", dependency_type="runtime", version_resolved=False)
    assert provider.lookup(dep) == []
    dep2 = Dependency(ecosystem="pypi", name="requests", version=None, manifest="requirements.txt", dependency_type="runtime", version_resolved=False)
    assert provider.lookup(dep2) == []

def test_fixture_vulnerability_metadata():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    vuln = provider.lookup(dep)[0]
    assert vuln.severity == "high"
    assert vuln.score == 7.2
    assert vuln.fixed_version == "4.17.21"
    assert vuln.source == "fixture"

def test_fixed_version_preservation():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="pypi", name="requests", version="2.25.0", manifest="requirements.txt", dependency_type="runtime", version_resolved=True)
    vuln = provider.lookup(dep)[0]
    assert vuln.fixed_version == "2.31.0"

# Finding integration tests
def test_scanner_name_sca():
    analyzer = SCAAnalyzer()
    manifests = {"package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})}
    result = analyzer.analyze(manifests)
    assert result["scanner"] == "sca"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["scanner"] == "sca"

def test_severity_preserved():
    analyzer = SCAAnalyzer()
    manifests = {"package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})}
    result = analyzer.analyze(manifests)
    assert result["findings"][0]["severity"] == "high"

def test_cve_preserved():
    analyzer = SCAAnalyzer()
    manifests = {"package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})}
    result = analyzer.analyze(manifests)
    assert result["findings"][0]["cve"] == "CVE-2021-23337"

def test_evidence_preserved():
    analyzer = SCAAnalyzer()
    manifests = {"package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})}
    result = analyzer.analyze(manifests)
    ev = result["findings"][0]["evidence"]
    assert "lodash" in ev
    assert "4.17.20" in ev
    assert "CVE-2021-23337" in ev

def test_remediation_preserved():
    analyzer = SCAAnalyzer()
    manifests = {"package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})}
    result = analyzer.analyze(manifests)
    assert "4.17.21" in result["findings"][0]["remediation"]

def test_duplicate_finding_suppression():
    analyzer = SCAAnalyzer()
    # Same vuln via two manifests (package.json range + lockfile exact) should deduplicate
    manifests = {
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.20"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}),
    }
    result = analyzer.analyze(manifests)
    assert len(result["findings"]) == 1

# Security tests
def test_no_subprocess_execution():
    import app.services.sca.analyzer as mod
    import inspect
    source = inspect.getsource(mod)
    assert "import subprocess" not in source
    assert "from subprocess" not in source
    assert "os.system" not in source
    assert "os.popen" not in source

def test_no_network_dependency():
    import inspect
    from app.services.sca import analyzer as mod
    source = inspect.getsource(mod)
    assert "requests.get" not in source
    assert "urllib.request" not in source
    assert "socket" not in source

def test_malformed_input_handled_safely():
    analyzer = SCAAnalyzer()
    result = analyzer.analyze({"package.json": "{invalid json"})
    assert len(result["errors"]) == 1
    assert "Invalid JSON" in result["errors"][0]["error"]
    assert result["dependencies"] == []

def test_oversized_input_handled():
    analyzer = SCAAnalyzer()
    big = "a" * (3 * 1024 * 1024)  # 3MB, over limit? Our limit is 2MB per manifest, 5MB for sca scanner
    # For analyzer limit is 2MB, so 3MB should error
    result = analyzer.analyze({"package.json": big})
    assert len(result["errors"]) == 1
    assert "size limit" in result["errors"][0]["error"].lower()

# Determinism tests
def test_repeated_parsing_identical():
    content = json.dumps({"dependencies": {"lodash": "^4.17.20"}})
    p1 = PackageJsonParser().parse(content)
    p2 = PackageJsonParser().parse(content)
    assert p1 == p2

def test_repeated_vulnerability_lookup_identical():
    provider = FixtureVulnerabilityProvider()
    dep = Dependency(ecosystem="npm", name="lodash", version="4.17.20", manifest="package-lock.json", dependency_type="runtime", version_resolved=True)
    assert provider.lookup(dep) == provider.lookup(dep)

def test_repeated_full_analysis_identical():
    analyzer = SCAAnalyzer()
    manifests = {"package-lock.json": json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})}
    r1 = analyzer.analyze(manifests)
    r2 = analyzer.analyze(manifests)
    assert r1 == r2
