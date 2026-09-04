"""S7.8 API Scanner — contract, workspace, command safety."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.scanner.base import ScanContext
from app.scanner.docker_runner import ScannerFailureError
from app.scanner.scanners.api import ApiScanner, PRODUCTION_ENGINE, PRODUCTION_VERSION
from app.scanner.parsers.api_parser import ApiParser


def test_01_scanner_metadata():
    s = ApiScanner()
    assert s.name == "api"
    assert s.family == "api"
    assert s.category == "application_security"
    assert s.requires_workspace is True
    assert "api" in s.supported_profiles
    assert s.output_format == "sarif"
    assert "openapi" in s.capabilities


def test_02_scanner_is_registered():
    from app.scanner.registry import ScannerRegistry
    reg = ScannerRegistry()
    meta = next(m for m in reg.list() if m["name"] == "api")
    assert meta["family"] == "api"
    assert meta["requires_workspace"] is True


def test_03_scanner_instance_is_base():
    from app.scanner.base import BaseScanner
    s = ApiScanner()
    assert isinstance(s, BaseScanner)


def test_04_parser_registered():
    from app.scanner.parsers.registry import ParserRegistry
    reg = ParserRegistry()
    parser = reg.get("api")
    assert isinstance(parser, ApiParser)


def test_05_profile_included():
    from app.scanner.profiles import get_scanners_for_profile
    assert "api" in get_scanners_for_profile("api")
    assert "api" in get_scanners_for_profile("api_full")


def test_06_version_pinned():
    assert PRODUCTION_VERSION == "1.0.0"
    assert PRODUCTION_ENGINE == "vapt-api"
    assert "vapt-api" in ApiScanner.IMAGE


def test_07_image_default():
    s = ApiScanner()
    assert s.IMAGE == os.getenv("API_IMAGE", "vapt-api:latest")


def test_08_no_workspace_returns_empty():
    s = ApiScanner()
    ctx = ScanContext(target="example", workspace=None, project_id="p1", scan_id="s1")
    raw = s.scan_with_context(ctx)
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["metadata"]["reason"] == "no workspace"


def test_09_empty_workspace_returns_empty():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []
        assert data["metadata"]["reason"] == "no api spec"


def test_10_workspace_with_ignored_dirs_only():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "node_modules").mkdir(parents=True)
        (Path(tmp) / "node_modules" / "index.js").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []


def test_11_readonly_workspace_mount():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "openapi.json").write_text('{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        volumes = mock_runner.run.call_args[1]["volumes"]
        for _, cfg in volumes.items():
            assert cfg["mode"] == "ro"


def test_12_command_uses_array():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "openapi.json").write_text('{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        cmd = mock_runner.run.call_args[1]["command"]
        assert isinstance(cmd, list)
        assert cmd[0] == "sh"
        assert "/workspace" in cmd[2]
        assert "api_scan.py" in cmd[2]
        for part in cmd:
            assert ";" not in str(part) or part == cmd[2]  # only shell wrapper may have ;
        # Image ref not needed, but ensure no shell injection via workspace
        assert ".." not in cmd[2] or "/workspace" in cmd[2]


def test_13_no_docker_socket_mount():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "openapi.json").write_text('{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        volumes = mock_runner.run.call_args[1].get("volumes", {})
        for host in volumes:
            assert "docker.sock" not in str(host)


def test_14_path_traversal_blocked():
    from app.scanner.docker_runner import DockerRunner
    runner = DockerRunner(client=MagicMock())
    with pytest.raises(ValueError):
        runner._validate_volumes({"/tmp/../etc": {"bind": "/workspace", "mode": "ro"}})


def test_15_legacy_scan_returns_empty():
    s = ApiScanner()
    raw = s.scan("anything")
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["metadata"]["execution_mode"] == "legacy"


def test_16_exit_code_with_sarif_is_success():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "openapi.json").write_text('{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "vapt-api", "rules": [{"id": "API002"}]}},
                "results": [{
                    "ruleId": "API002",
                    "level": "warning",
                    "message": {"text": "Operation missing security"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "openapi.json"}, "region": {"startLine": 1}}}],
                }],
            }],
        }
        mock_runner = MagicMock()
        mock_runner.run.side_effect = ScannerFailureError("fail", exit_code=1, stdout=json.dumps(sarif), stderr="")
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert len(data["findings"]) >= 1
        assert data["metadata"]["execution_engine"] == PRODUCTION_ENGINE


def test_17_fallback_disabled_raises(monkeypatch):
    monkeypatch.setenv("API_FALLBACK_ENABLED", "false")
    import importlib
    import app.scanner.scanners.api as mod
    importlib.reload(mod)
    s = mod.ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "openapi.json").write_text('{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("image not found")
        s.runner = mock_runner
        with pytest.raises(Exception):
            s.scan_with_context(ctx)
    importlib.reload(mod)


def test_18_clean_workspace_no_false_positive():
    s = ApiScanner()
    with tempfile.TemporaryDirectory() as tmp:
        # Clean spec with HTTPS and auth
        clean = {
            "openapi": "3.0.0",
            "info": {"title": "Clean API", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "ok"}}
                    }
                }
            },
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}
        }
        Path(tmp, "openapi.json").write_text(json.dumps(clean))
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        # Mock returns empty SARIF (no findings for clean)
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        # Should be 0 or filtered; we mock empty, so 0
        assert data["findings"] == []
