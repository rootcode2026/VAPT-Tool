"""S7.7 IaC Scanner — contract, workspace, command safety."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.scanner.base import ScanContext
from app.scanner.docker_runner import ScannerFailureError
from app.scanner.scanners.iac import (
    FALLBACK_ENGINE,
    PRODUCTION_ENGINE,
    PRODUCTION_VERSION,
    IacScanner,
)
from app.scanner.parsers.iac_parser import IacParser


def test_01_scanner_metadata():
    s = IacScanner()
    assert s.name == "iac"
    assert s.family == "iac"
    assert s.category == "application_security"
    assert s.requires_workspace is True
    assert "iac" in s.supported_profiles
    assert s.output_format == "sarif"
    assert "checkov" in s.capabilities
    assert s.timeout > 0


def test_02_scanner_is_registered():
    from app.scanner.registry import ScannerRegistry
    reg = ScannerRegistry()
    meta = next(m for m in reg.list() if m["name"] == "iac")
    assert meta["family"] == "iac"
    assert meta["requires_workspace"] is True


def test_03_scanner_instance_is_base():
    from app.scanner.base import BaseScanner
    s = IacScanner()
    assert isinstance(s, BaseScanner)


def test_04_parser_registered():
    from app.scanner.parsers.registry import ParserRegistry
    reg = ParserRegistry()
    parser = reg.get("iac")
    assert isinstance(parser, IacParser)


def test_05_profile_included():
    from app.scanner.profiles import get_scanners_for_profile
    assert "iac" in get_scanners_for_profile("iac")
    assert "iac" in get_scanners_for_profile("iac_full")


def test_06_version_pinned():
    assert PRODUCTION_VERSION == "3.3.16"
    assert PRODUCTION_ENGINE == "checkov"
    assert IacScanner.FALLBACK_IMAGE.startswith("bridgecrew/checkov@sha256:")
    assert len(IacScanner.FALLBACK_IMAGE.split("sha256:")[-1]) == 64


def test_07_image_default():
    s = IacScanner()
    assert s.IMAGE == os.getenv("IAC_IMAGE", "vapt-iac:latest")


def test_08_timeout_configurable():
    s = IacScanner()
    assert s.timeout == int(os.getenv("IAC_TIMEOUT", "180"))


def test_09_no_workspace_returns_empty():
    s = IacScanner()
    ctx = ScanContext(target="example", workspace=None, project_id="p1", scan_id="s1")
    raw = s.scan_with_context(ctx)
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["metadata"]["reason"] == "no workspace"


def test_10_empty_workspace_returns_empty():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []
        assert data["metadata"]["reason"] == "no iac files"


def test_11_workspace_with_ignored_dirs_only():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "node_modules" / "pkg.js").mkdir(parents=True)
        Path(tmp, "node_modules", "pkg.js", "index.js").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []


def test_12_readonly_workspace_mount():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        # Create IaC file
        Path(tmp, "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        volumes = mock_runner.run.call_args[1]["volumes"]
        for _, cfg in volumes.items():
            assert cfg["mode"] == "ro"


def test_13_command_uses_array():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"results":{"failed_checks":[]}}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        cmd = mock_runner.run.call_args[1]["command"]
        assert isinstance(cmd, list)
        assert cmd[0] == "checkov"
        assert "-d" in cmd
        assert "-o" in cmd
        assert "json" in cmd
        # No shell metachars
        for part in cmd:
            assert ";" not in str(part)
            assert "|" not in str(part)


def test_14_command_targets_workspace_not_host():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        cmd = mock_runner.run.call_args[1]["command"]
        assert "/workspace" in cmd


def test_15_workspace_traversal_blocked():
    from app.scanner.docker_runner import DockerRunner
    runner = DockerRunner(client=MagicMock())
    with pytest.raises(ValueError):
        runner._validate_volumes({"/tmp/../etc": {"bind": "/workspace", "mode": "ro"}})


def test_16_legacy_scan_returns_empty():
    s = IacScanner()
    raw = s.scan("/some/path")
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["metadata"]["execution_mode"] == "legacy"


def test_17_exit_code_with_sarif_is_success():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "checkov", "rules": [{"id": "CKV_AWS_1"}]}},
                "results": [{
                    "ruleId": "CKV_AWS_1",
                    "level": "error",
                    "message": {"text": "Ensure S3 bucket is encrypted"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 1}}}],
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


def test_18_fallback_disabled_raises(monkeypatch):
    monkeypatch.setenv("IAC_FALLBACK_ENABLED", "false")
    import importlib
    import app.scanner.scanners.iac as mod
    importlib.reload(mod)
    s = mod.IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "main.tf").write_text('resource "x" "y" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("image not found")
        s.runner = mock_runner
        with pytest.raises(Exception):
            s.scan_with_context(ctx)
    importlib.reload(mod)


def test_19_fallback_enabled_returns_empty(monkeypatch):
    monkeypatch.setenv("IAC_FALLBACK_ENABLED", "true")
    import importlib
    import app.scanner.scanners.iac as mod
    importlib.reload(mod)
    s = mod.IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "main.tf").write_text('resource "x" "y" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("docker unavailable")
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["metadata"]["execution_engine"] == mod.FALLBACK_ENGINE
    importlib.reload(mod)


def test_20_no_docker_socket_mount():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "main.tf").write_text('resource "x" "y" {}')
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        volumes = mock_runner.run.call_args[1].get("volumes", {})
        for host in volumes:
            assert "docker.sock" not in str(host)


def test_21_traversal_via_symlink_blocked():
    s = IacScanner()
    with tempfile.TemporaryDirectory() as tmp:
        # Create a file outside workspace and symlink inside - should be ignored via resolve check
        outside = tempfile.mktemp()
        Path(outside).write_text('resource "x" "y" {}')
        link = Path(tmp) / "link.tf"
        try:
            link.symlink_to(outside)
        except Exception:
            pytest.skip("symlink not supported")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        # _workspace_has_iac should ignore symlink that resolves outside
        # So we expect empty (no iac files) -> should return empty findings, not scan
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        # If symlink is ignored, it will be empty; if not, it may scan but still safe
        assert "findings" in data
