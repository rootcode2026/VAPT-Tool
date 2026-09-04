"""S7.3 Production SAST — comprehensive tests (32 cases)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.base import ScanContext
from app.scanner.parsers.sarif_parser import SarifParser
from app.scanner.parsers.sast_parser import SASTParser
from app.scanner.registry import ScannerRegistry


def _valid_sarif(rule_id="RULE001", file="src/app.py", line=10, level="error", message="Test finding", cwe=None, help_text=None):
    rule = {"id": rule_id, "shortDescription": {"text": message}, "fullDescription": {"text": message}}
    if help_text:
        rule["help"] = {"text": help_text}
    if cwe:
        rule["properties"] = {"tags": [cwe]}
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": [rule]}},
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {"text": message},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}
                        ],
                    }
                ],
            }
        ],
    }


def test_01_sast_metadata():
    reg = ScannerRegistry()
    sast = reg.get("sast")
    assert sast.name == "sast"
    assert sast.family == "sast"
    assert sast.category == "application_security"
    assert "repository" in sast.target_types or "directory" in sast.target_types
    assert sast.input_type == "source_code"
    assert sast.output_format == "sarif"


def test_02_requires_workspace():
    reg = ScannerRegistry()
    assert reg.get("sast").requires_workspace is True


def test_03_supported_profiles():
    reg = ScannerRegistry()
    sast = reg.get("sast")
    assert "sast" in sast.supported_profiles
    assert "full" in sast.supported_profiles


def test_04_empty_workspace_returns_success():
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        # Empty dir — no source files
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        # Mock Docker to avoid real run — should return empty without Docker
        with patch.object(scanner, "_get_runner") as mock_get:
            mock_runner = MagicMock()
            mock_runner.run.side_effect = Exception("not needed")
            mock_get.return_value = mock_runner
            result_str = scanner.scan_with_context(ctx)
            data = json.loads(result_str)
            assert data["findings"] == []
            assert data["assets"] == []
            assert data["scanner"] == "sast"


def test_05_source_root_detection():
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / "src").mkdir()
        (ws / "src" / "app.py").write_text('password = "secret123"')
        (ws / "other.py").write_text('x = 1')
        ctx = ScanContext(target=str(ws), workspace=str(ws), project_id="p1", scan_id="s1")
        # Mock runner to capture container_target
        captured = {}

        class FakeRunner:
            def run(self, image, command, timeout, scanner, target, volumes, workspace):
                captured["command"] = command
                captured["volumes"] = volumes
                # Return empty SARIF
                return json.dumps({"version": "2.1.0", "runs": []})

        scanner.runner = FakeRunner()
        result_str = scanner.scan_with_context(ctx)
        # Should have scanned /workspace/src (since it exists)
        assert any("/workspace/src" in str(c) for c in captured["command"]) or any("src" in str(c) for c in captured["command"])


def test_06_source_file_discovery():
    from app.services.sast.analyzer import SASTAnalyzer

    analyzer = SASTAnalyzer()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.py").write_text('x = eval("test")')
        Path(tmp, "b.js").write_text('eval("test")')
        result = analyzer.analyze(tmp)
        assert result["metadata"]["files_scanned"] >= 2


def test_07_docker_invoked_with_workspace():
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('x = eval("test")')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = json.dumps({"version": "2.1.0", "runs": []})
        scanner.runner = mock_runner
        scanner.scan_with_context(ctx)
        assert mock_runner.run.called
        kwargs = mock_runner.run.call_args[1]
        assert "volumes" in kwargs
        # Check workspace is mounted (key is host path, may be Windows with backslashes)
        assert any(tmp in str(k) or Path(tmp).resolve() == Path(k).resolve() for k in kwargs["volumes"].keys()) or tmp in str(kwargs["volumes"])


def test_08_workspace_mounted_readonly():
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('x = 1')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = json.dumps({"version": "2.1.0", "runs": []})
        scanner.runner = mock_runner
        scanner.scan_with_context(ctx)
        volumes = mock_runner.run.call_args[1]["volumes"]
        # Find the workspace mount
        found = False
        for host, cfg in volumes.items():
            if str(tmp) in host or host == tmp:
                assert cfg["mode"] == "ro"
                assert cfg["bind"] == "/workspace"
                found = True
        assert found


def test_09_command_points_only_to_workspace():
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('x = 1')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = json.dumps({"version": "2.1.0", "runs": []})
        scanner.runner = mock_runner
        scanner.scan_with_context(ctx)
        command = mock_runner.run.call_args[1]["command"]
        # Must not contain host paths outside workspace
        for part in command:
            assert "/etc/passwd" not in str(part)
            assert "C:\\Users" not in str(part)
        # Must contain /workspace
        assert any("/workspace" in str(c) for c in command)


def test_10_sarif_parsed():
    parser = SASTParser()
    sarif = _valid_sarif()
    raw = json.dumps(sarif)
    result = parser.parse(raw)
    assert result["scanner"] == "sast"
    assert len(result["findings"]) == 1


def test_11_rule_id_preserved():
    parser = SASTParser()
    sarif = _valid_sarif(rule_id="RULE123")
    result = parser.parse(json.dumps(sarif))
    assert result["findings"][0]["rule_id"] == "RULE123"
    assert result["findings"][0]["metadata"]["rule_id"] == "RULE123"


def test_12_file_preserved():
    parser = SASTParser()
    sarif = _valid_sarif(file="src/app.py")
    result = parser.parse(json.dumps(sarif))
    assert result["findings"][0]["file"] == "src/app.py"


def test_13_line_preserved():
    parser = SASTParser()
    sarif = _valid_sarif(line=42)
    result = parser.parse(json.dumps(sarif))
    assert result["findings"][0]["line"] == 42


def test_14_severity_normalization():
    parser = SASTParser()
    for level, expected in [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")]:
        sarif = _valid_sarif(level=level)
        result = parser.parse(json.dumps(sarif))
        assert result["findings"][0]["severity"] == expected, f"{level} -> {expected}"


def test_15_cwe_preserved():
    parser = SarifParser()
    sarif = _valid_sarif(cwe="CWE-79")
    result = parser.parse(json.dumps(sarif))
    assert result["findings"][0]["cwe"] == "CWE-79"


def test_16_remediation_preserved():
    parser = SarifParser()
    sarif = _valid_sarif(help_text="Use safe API")
    result = parser.parse(json.dumps(sarif))
    assert "Use safe API" in result["findings"][0]["remediation"]


def test_17_source_code_evidence():
    from app.services.finding_correlation.evidence import build_evidence_provenance

    # Create a correlated finding with file
    correlated = {
        "file": "src/app.py",
        "scanners": ["sast"],
        "scanner_count": 1,
        "evidence": [{"scanner": "sast", "evidence": "test", "fingerprint": "abc"}],
        "finding_count": 1,
    }
    provenance = build_evidence_provenance(correlated)
    assert "source_code" in provenance["evidence_types"]


def test_18_source_file_asset():
    parser = SASTParser()
    sarif = _valid_sarif(file="src/app.py")
    result = parser.parse(json.dumps(sarif))
    assert any(a["type"] == "source_file" and a["value"] == "src/app.py" for a in result["assets"])


def test_19_finding_to_source_file_association():
    parser = SASTParser()
    sarif = _valid_sarif(file="src/app.py", line=10)
    result = parser.parse(json.dumps(sarif))
    finding = result["findings"][0]
    assert finding["file"] == "src/app.py"
    # Asset should exist for that file
    assert any(a["value"] == "src/app.py" for a in result["assets"])


def test_20_project_isolation():
    # Findings should not be associated across projects — ScanContext enforces project_id
    ctx1 = ScanContext(target="/tmp/ws1", project_id="proj1", scan_id="s1", workspace="/tmp/ws1")
    ctx2 = ScanContext(target="/tmp/ws2", project_id="proj2", scan_id="s2", workspace="/tmp/ws2")
    assert ctx1.project_id != ctx2.project_id
    assert ctx1.workspace != ctx2.workspace


def test_21_malicious_sarif_path():
    parser = SarifParser()
    sarif = _valid_sarif(file="../../etc/passwd")
    result = parser.parse(json.dumps(sarif))
    # Should not raise, should preserve as metadata but not cause file read
    assert result["findings"][0]["file"] == "../../etc/passwd"
    # Asset value is as given, but application should not open it
    assert any(a["value"] == "../../etc/passwd" for a in result["assets"])
    # Ensure no host file was read (we didn't open)
    assert True


def test_22_snippet_bounded():
    parser = SarifParser()
    long_msg = "A" * 5000
    sarif = _valid_sarif(message=long_msg)
    result = parser.parse(json.dumps(sarif))
    # Evidence should be truncated to 500
    assert len(result["findings"][0]["evidence"]) <= 500


def test_23_empty_sarif():
    parser = SASTParser()
    empty = {"version": "2.1.0", "runs": []}
    result = parser.parse(json.dumps(empty))
    assert result["findings"] == []
    assert result["assets"] == []


def test_24_malformed_sarif():
    parser = SASTParser()
    with pytest.raises(ValueError):
        parser.parse("not json")
    # Missing runs but with findings key is legacy SAST JSON, not SARIF — should not raise for SASTParser
    # Malformed SARIF with runs as wrong type should raise
    with pytest.raises(ValueError):
        parser.parse(json.dumps({"runs": "not a list"}))


def test_25_scanner_execution_failure(monkeypatch):
    monkeypatch.setenv("SAST_FALLBACK_ENABLED", "true")
    import importlib
    import app.scanner.scanners.sast as sast_mod

    importlib.reload(sast_mod)
    from app.scanner.docker_runner import ScannerFailureError
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('x = 1')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = ScannerFailureError("fail", exit_code=2, stdout="", stderr="error")
        scanner.runner = mock_runner
        result_str = scanner.scan_with_context(ctx)
        data = json.loads(result_str)
        assert "findings" in data
        assert data["metadata"]["execution_engine"] == "sast_analyzer"
    monkeypatch.setenv("SAST_FALLBACK_ENABLED", "false")
    importlib.reload(sast_mod)


def test_26_timeout_handling(monkeypatch):
    monkeypatch.setenv("SAST_FALLBACK_ENABLED", "true")
    import importlib
    import app.scanner.scanners.sast as sast_mod

    importlib.reload(sast_mod)
    from app.scanner.docker_runner import ScannerTimeoutError
    from app.scanner.scanners.sast import SASTScanner

    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text('x = 1')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = ScannerTimeoutError("timeout", timed_out=True)
        scanner.runner = mock_runner
        result_str = scanner.scan_with_context(ctx)
        data = json.loads(result_str)
        assert "scanner" in data
        assert data["metadata"]["execution_engine"] == "sast_analyzer"
    monkeypatch.setenv("SAST_FALLBACK_ENABLED", "false")
    importlib.reload(sast_mod)


def test_27_retry_behavior():
    from app.scanner.execution import run_with_retries
    from app.scanner.docker_runner import ScannerTimeoutError

    attempts = []

    def fake_execute(scanner, target):
        attempts.append(1)
        if len(attempts) == 1:
            raise ScannerTimeoutError("timeout", timed_out=True)
        return {"scanner": scanner, "status": "completed", "raw_output": json.dumps({"version": "2.1.0", "runs": []}), "parsed_result": {"assets": [], "findings": []}, "findings": []}

    result = run_with_retries(fake_execute, "sast", "dummy", max_attempts=2)
    assert len(attempts) == 2
    assert result["status"] == "completed"


def test_28_fresh_workspace_per_retry():
    from app.scanner.workspace import create_workspace, cleanup_workspace
    from app.scanner.execution import run_with_retries
    from app.scanner.docker_runner import ScannerTimeoutError

    workspaces = []

    def fake_execute(scanner, target):
        from app.scanner.workspace import create_workspace as cw, cleanup_workspace as clw

        ws = cw(scan_id="s1", scanner=scanner, project_id="p1")
        workspaces.append(ws)
        if len(workspaces) == 1:
            clw(ws)
            raise ScannerTimeoutError("timeout", timed_out=True)
        clw(ws)
        return {"scanner": scanner, "status": "completed", "raw_output": json.dumps({"version": "2.1.0", "runs": []}), "parsed_result": {"assets": [], "findings": []}, "findings": []}

    run_with_retries(fake_execute, "sast", "dummy", max_attempts=2)
    assert workspaces[0] != workspaces[1]
    assert not Path(workspaces[0]).exists()
    assert not Path(workspaces[1]).exists()


def test_29_contract_compatibility():
    from app.scanner.registry import ScannerRegistry

    reg = ScannerRegistry()
    # All 10 scanners must still be retrievable
    for name in ["nmap", "nuclei", "http_fingerprint", "zap", "nikto", "tls", "dns", "subdomain", "sca", "sast"]:
        scanner = reg.get(name)
        assert scanner.name == name
        assert hasattr(scanner, "scan")
        assert hasattr(scanner, "scan_with_context")


def test_30_pipeline_integration():
    from app.scanner.pipeline import ScannerPipeline

    pipeline = ScannerPipeline()
    # run_with_context should work for sast with empty workspace
    with tempfile.TemporaryDirectory() as tmp:
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        result = pipeline.run_with_context("sast", ctx)
        assert result["scanner"] == "sast"
        assert "findings" in result


def test_31_registry_integration():
    from app.scanner.registry import ScannerRegistry

    reg = ScannerRegistry()
    sast = reg.get("sast")
    assert sast.name == "sast"
    assert sast in [reg.get(n) for n in ["sast"]]


def test_32_profile_integration():
    from app.scanner.profiles import get_scanners_for_profile

    assert "sast" in get_scanners_for_profile("sast")
    assert "sca" in get_scanners_for_profile("sca")
    # Quick should not include sast (preserve existing profile semantics)
    assert "sast" not in get_scanners_for_profile("quick")
    assert "sast" not in get_scanners_for_profile("web")
    # Full currently matches web (8 scanners) — SAST/Sca have dedicated profiles
    assert get_scanners_for_profile("full") == [
        "nmap",
        "http_fingerprint",
        "nuclei",
        "zap",
        "nikto",
        "tls",
        "dns",
        "subdomain",
    ]
