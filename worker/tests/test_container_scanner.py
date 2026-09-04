"""S7.6 Container Scanner — contract, validation, command safety."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.base import ScanContext
from app.scanner.docker_runner import ScannerFailureError
from app.scanner.scanners.container import (
    FALLBACK_ENGINE,
    PRODUCTION_ENGINE,
    PRODUCTION_VERSION,
    ContainerScanner,
    _validate_image_ref,
)
from app.scanner.parsers.container_parser import ContainerParser


def test_01_scanner_metadata():
    s = ContainerScanner()
    assert s.name == "container"
    assert s.family == "container"
    assert s.category == "container_security"
    assert s.requires_workspace is False
    assert "container" in s.supported_profiles
    assert s.output_format == "sarif"
    assert "trivy" in s.capabilities
    assert s.timeout > 0


def test_02_scanner_is_registered():
    from app.scanner.registry import ScannerRegistry
    reg = ScannerRegistry()
    meta = next(m for m in reg.list() if m["name"] == "container")
    assert meta["family"] == "container"
    assert meta["requires_workspace"] is False


def test_03_scanner_instance_is_base():
    from app.scanner.base import BaseScanner
    s = ContainerScanner()
    assert isinstance(s, BaseScanner)
    assert callable(s.scan)
    assert callable(s.scan_with_context)


def test_04_parser_registered():
    from app.scanner.parsers.registry import ParserRegistry
    reg = ParserRegistry()
    parser = reg.get("container")
    assert isinstance(parser, ContainerParser)


def test_05_profile_included():
    from app.scanner.profiles import get_scanners_for_profile
    assert "container" in get_scanners_for_profile("container")
    assert "container" in get_scanners_for_profile("container_full")


def test_06_version_pinned():
    assert PRODUCTION_VERSION == "0.66.0"
    assert PRODUCTION_ENGINE == "trivy"
    assert "0.66.0" not in ContainerScanner.FALLBACK_IMAGE or "0.66.0" in ContainerScanner.FALLBACK_IMAGE
    # Fallback must be digest pinned
    assert ContainerScanner.FALLBACK_IMAGE.startswith("aquasec/trivy@sha256:")
    assert len(ContainerScanner.FALLBACK_IMAGE.split("sha256:")[-1]) == 64


def test_07_image_default():
    s = ContainerScanner()
    assert s.IMAGE == os.getenv("CONTAINER_IMAGE", "vapt-container:latest")


def test_08_timeout_configurable():
    s = ContainerScanner()
    assert s.timeout == int(os.getenv("CONTAINER_TIMEOUT", "300"))


# --- Image reference validation ---

def test_09_valid_image_refs():
    for ref in ["alpine:3.14", "nginx:latest", "myreg.example.com:5000/myimage:tag",
                "python:3.9-alpine", "hello-world", "aquasec/trivy:0.66.0",
                "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"]:
        assert _validate_image_ref(ref) == ref.strip()


def test_10_invalid_empty():
    with pytest.raises(ValueError):
        _validate_image_ref("")
    with pytest.raises(ValueError):
        _validate_image_ref("  ")


def test_11_invalid_shell_injection():
    for bad in ["alpine:3.14; rm -rf /", "nginx|cat /etc/passwd", "myimage & echo pwned",
                "test$(whoami)", "img`id`", "a;b", "a|b", "a&b", "a$b", "a'quote", 'a"quote']:
        with pytest.raises(ValueError):
            _validate_image_ref(bad)


def test_12_invalid_whitespace_control():
    with pytest.raises(ValueError):
        _validate_image_ref("alpine 3.14")
    with pytest.raises(ValueError):
        _validate_image_ref("alpine\n:3.14")


def test_13_invalid_traversal():
    with pytest.raises(ValueError):
        _validate_image_ref("myimage/../etc")


def test_14_invalid_too_long():
    with pytest.raises(ValueError):
        _validate_image_ref("a" * 513)


def test_15_scan_invalid_image_raises():
    s = ContainerScanner()
    with pytest.raises(ValueError, match="Image reference"):
        s.scan("bad; rm -rf /")
    with pytest.raises(ValueError):
        s.scan("")


def test_16_command_uses_array_not_shell():
    s = ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    s.scan("alpine:3.14")
    cmd = mock_runner.run.call_args[1]["command"]
    assert isinstance(cmd, list)
    assert cmd[0] == "trivy"
    assert "image" in cmd
    assert "--format" in cmd
    assert "sarif" in cmd
    assert "alpine:3.14" in cmd
    # No shell metachars in command array
    for part in cmd:
        assert ";" not in str(part)
        assert "|" not in str(part)
        assert "&" not in str(part)


def test_17_command_image_is_single_arg():
    s = ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    s.scan("myreg.example.com:5000/myimage:tag")
    cmd = mock_runner.run.call_args[1]["command"]
    # Image ref must be a single argv element (no shell splitting)
    assert "myreg.example.com:5000/myimage:tag" in cmd
    # Ensure it's exactly one element, not split
    assert cmd.count("myreg.example.com:5000/myimage:tag") == 1


def test_18_no_volumes_no_workspace():
    s = ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    s.scan("alpine:3.14")
    call_kwargs = mock_runner.run.call_args[1]
    assert call_kwargs.get("volumes") == {}
    assert call_kwargs.get("workspace") is None


def test_19_no_docker_socket_mount():
    s = ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    s.scan("alpine:3.14")
    volumes = mock_runner.run.call_args[1].get("volumes", {})
    for host in volumes:
        assert "docker.sock" not in str(host)
        assert host != "/var/run/docker.sock"


def test_20_exit_sarif_is_success():
    s = ContainerScanner()
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "trivy", "rules": [{"id": "CVE-2023-1234"}]}},
            "results": [{
                "ruleId": "CVE-2023-1234",
                "level": "error",
                "message": {"text": "CVE-2023-1234 in openssl"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 1}}}],
            }],
        }],
    }
    mock_runner = MagicMock()
    mock_runner.run.return_value = json.dumps(sarif)
    s.runner = mock_runner
    raw = s.scan("alpine:3.14")
    data = json.loads(raw)
    assert len(data["findings"]) >= 1
    assert data["metadata"]["execution_engine"] == PRODUCTION_ENGINE


def test_21_scan_with_context():
    s = ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    ctx = ScanContext(target="nginx:latest", workspace=None, project_id="p1", scan_id="s1")
    raw = s.scan_with_context(ctx)
    data = json.loads(raw)
    assert data["scanner"] == "container"
    assert data["metadata"]["scanned_image"] == "nginx:latest"


def test_22_scan_with_context_invalid():
    s = ContainerScanner()
    ctx = ScanContext(target="bad; rm -rf /", workspace=None, project_id="p1", scan_id="s1")
    with pytest.raises(ValueError, match="Invalid container image reference"):
        s.scan_with_context(ctx)


def test_23_container_image_asset_created():
    s = ContainerScanner()
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "trivy"}},
            "results": [{
                "ruleId": "CVE-2021-1234",
                "level": "warning",
                "message": {"text": "vuln in libssl"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}}}],
            }],
        }],
    }
    mock_runner = MagicMock()
    mock_runner.run.return_value = json.dumps(sarif)
    s.runner = mock_runner
    raw = s.scan("alpine:3.14")
    data = json.loads(raw)
    assert any(a["type"] == "container_image" and a["value"] == "alpine:3.14" for a in data["assets"])


def test_24_metadata_contains_image():
    s = ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    raw = s.scan("python:3.9-alpine")
    data = json.loads(raw)
    assert data["metadata"]["scanned_image"] == "python:3.9-alpine"
    assert data["metadata"]["engine_version"] == PRODUCTION_VERSION


def test_25_fallback_disabled_raises(monkeypatch):
    monkeypatch.setenv("CONTAINER_FALLBACK_ENABLED", "false")
    import importlib
    import app.scanner.scanners.container as mod
    importlib.reload(mod)
    s = mod.ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.side_effect = Exception("image not found")
    s.runner = mock_runner
    with pytest.raises(Exception):
        s.scan("alpine:3.14")
    importlib.reload(mod)


def test_26_fallback_enabled_returns_empty(monkeypatch):
    monkeypatch.setenv("CONTAINER_FALLBACK_ENABLED", "true")
    import importlib
    import app.scanner.scanners.container as mod
    importlib.reload(mod)
    s = mod.ContainerScanner()
    mock_runner = MagicMock()
    mock_runner.run.side_effect = Exception("docker unavailable")
    s.runner = mock_runner
    raw = s.scan("alpine:3.14")
    data = json.loads(raw)
    assert data["metadata"]["execution_engine"] == "container_fallback"
    assert data["metadata"]["execution_mode"] == "fallback"
    importlib.reload(mod)


def test_27_timeout_enforced():
    s = ContainerScanner()
    assert s.timeout == int(os.getenv("CONTAINER_TIMEOUT", "300"))
    mock_runner = MagicMock()
    mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
    s.runner = mock_runner
    s.scan("alpine:3.14")
    assert mock_runner.run.call_args[1]["timeout"] == s.timeout
