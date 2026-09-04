"""S7.5 Secrets Scanner — Production hardening tests.

Tests scanner metadata, workspace handling, command construction,
Docker invocation, redaction, and security properties.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.base import ScanContext
from app.scanner.docker_runner import ScannerFailureError
from app.scanner.scanners.secrets import (
    FALLBACK_ENGINE,
    PRODUCTION_ENGINE,
    PRODUCTION_VERSION,
    REDACTED,
    SecretsScanner,
    _redact_sarif,
    _redact_text,
    _secret_hash,
)
from app.scanner.parsers.secrets_parser import SecretsParser


# ---------------------------------------------------------------------------
# Scanner metadata and contract
# ---------------------------------------------------------------------------

def test_01_scanner_metadata():
    s = SecretsScanner()
    assert s.name == "secrets"
    assert s.family == "secrets"
    assert s.category == "application_security"
    assert s.requires_workspace is True
    assert "secrets" in s.supported_profiles
    assert s.output_format == "sarif"
    assert s.timeout > 0
    assert "gitleaks" in s.capabilities


def test_02_scanner_is_registered():
    from app.scanner.registry import ScannerRegistry
    reg = ScannerRegistry()
    meta = next(m for m in reg.list() if m["name"] == "secrets")
    assert meta["family"] == "secrets"
    assert meta["requires_workspace"] is True


def test_03_scanner_instance_is_base():
    from app.scanner.base import BaseScanner
    s = SecretsScanner()
    assert isinstance(s, BaseScanner)
    assert callable(s.scan)
    assert callable(s.scan_with_context)


def test_04_parser_registered():
    from app.scanner.parsers.registry import ParserRegistry
    reg = ParserRegistry()
    parser = reg.get("secrets")
    assert isinstance(parser, SecretsParser)


def test_05_profile_included():
    from app.scanner.profiles import get_scanners_for_profile
    scanners = get_scanners_for_profile("secrets")
    assert "secrets" in scanners


def test_06_version_pinned():
    assert PRODUCTION_VERSION == "8.30.1"
    assert PRODUCTION_ENGINE == "gitleaks"
    assert "8.24.1" not in SecretsScanner.FALLBACK_IMAGE


def test_06b_fallback_image_digest_pinned():
    assert SecretsScanner.FALLBACK_IMAGE.startswith("zricethezav/gitleaks@sha256:")
    assert len(SecretsScanner.FALLBACK_IMAGE.split("sha256:")[-1]) == 64


def test_07_image_default():
    s = SecretsScanner()
    assert s.IMAGE == os.getenv("SECRETS_IMAGE", "vapt-secrets:latest")


def test_08_timeout_configurable():
    s = SecretsScanner()
    default_timeout = int(os.getenv("SECRETS_TIMEOUT", "120"))
    assert s.timeout == default_timeout


# ---------------------------------------------------------------------------
# Workspace handling
# ---------------------------------------------------------------------------

def test_09_no_workspace_returns_empty():
    s = SecretsScanner()
    ctx = ScanContext(target="example.com", workspace=None, project_id="p1", scan_id="s1")
    raw = s.scan_with_context(ctx)
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["metadata"]["reason"] == "no workspace"


def test_10_empty_workspace_returns_empty():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []
        assert data["metadata"]["reason"] == "no files"


def test_11_workspace_with_ignored_dirs_only():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "node_modules" / "pkg.js").mkdir(parents=True)
        (Path(tmp) / "node_modules" / "pkg.js" / "index.js").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []


def test_12_workspace_traversal_blocked():
    from app.scanner.docker_runner import DockerRunner
    runner = DockerRunner(client=MagicMock())
    with pytest.raises(ValueError):
        runner._validate_volumes({"/tmp/../etc": {"bind": "/workspace", "mode": "ro"}})


def test_13_readonly_workspace_mount():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "config.py").write_text("API_KEY = 'test'")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        call_kwargs = mock_runner.run.call_args
        volumes = call_kwargs[1]["volumes"] if "volumes" in call_kwargs[1] else call_kwargs[1].get("volumes", {})
        # Check that volumes are read-only
        for host_path, cfg in volumes.items():
            assert cfg["mode"] == "ro"


def test_14_workspace_cleanup_after_scan():
    from app.scanner.workspace import create_workspace, cleanup_workspace
    ws = create_workspace(scan_id="test123", scanner="secrets", project_id="proj1")
    assert Path(ws).exists()
    cleanup_workspace(ws)
    assert not Path(ws).exists()


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

def test_15_command_uses_array_not_shell():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "test.py").write_text("x = 1")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        cmd = mock_runner.run.call_args[1]["command"]
        assert isinstance(cmd, list)
        # Secrets uses sh -c wrapper to cat SARIF file to stdout (like SCA).
        # This is the one allowed sh -c pattern — deterministic, no untrusted interpolation.
        assert cmd[0] == "sh"
        assert cmd[1] == "-c"
        shell_script = cmd[2]
        assert "gitleaks" in shell_script
        assert "--no-git" in shell_script
        assert "--redact" in shell_script
        assert "cat /tmp/sarif.json" in shell_script
        # Wrapper must be deterministic and safe — only fixed constants interpolated
        assert "gitleaks detect --source" in shell_script
        # No Python shell=True — DockerRunner receives array, not string
        assert isinstance(cmd, list) and len(cmd) == 3


def test_16_command_targets_workspace_not_host():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "app.py").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        cmd = mock_runner.run.call_args[1]["command"]
        # sh -c wrapper: workspace mount target is fixed /workspace
        shell_script = cmd[2] if cmd[0] == "sh" else " ".join(cmd)
        assert "/workspace" in shell_script
        assert "/tmp/sarif.json" in shell_script
        # No host-absolute paths leaked into container command
        for part in cmd:
            assert not str(part).startswith("/etc/")
            assert not str(part).startswith("/var/")


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------

def test_17_legacy_scan_returns_empty():
    s = SecretsScanner()
    raw = s.scan("/some/path")
    data = json.loads(raw)
    assert data["findings"] == []
    assert data["metadata"]["execution_mode"] == "legacy"


# ---------------------------------------------------------------------------
# Docker execution with mocked findings
# ---------------------------------------------------------------------------

def test_18_exit_code_1_with_sarif_is_success():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "config.py").write_text("password = 'test'")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "gitleaks", "rules": [{"id": "generic-api-key"}]}},
                "results": [{
                    "ruleId": "generic-api-key",
                    "level": "warning",
                    "message": {"text": "Generic API Key detected"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "config.py"},
                        "region": {"startLine": 1, "startColumn": 20}
                    }}],
                }],
            }],
        }
        mock_runner = MagicMock()
        mock_runner.run.side_effect = ScannerFailureError(
            "fail", exit_code=1, stdout=json.dumps(sarif), stderr=""
        )
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert len(data["findings"]) >= 1
        assert data["metadata"]["execution_engine"] == PRODUCTION_ENGINE


def test_19_fallback_disabled_raises(monkeypatch):
    monkeypatch.setenv("SECRETS_FALLBACK_ENABLED", "false")
    import importlib
    import app.scanner.scanners.secrets as mod
    importlib.reload(mod)

    s = mod.SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "a.py").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("image not found")
        s.runner = mock_runner
        with pytest.raises(Exception):
            s.scan_with_context(ctx)
    importlib.reload(mod)


def test_20_fallback_enabled_returns_empty(monkeypatch):
    monkeypatch.setenv("SECRETS_FALLBACK_ENABLED", "true")
    import importlib
    import app.scanner.scanners.secrets as mod
    importlib.reload(mod)

    s = mod.SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "a.py").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("docker unavailable")
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["metadata"]["execution_engine"] == FALLBACK_ENGINE
        assert data["metadata"]["execution_mode"] == "fallback"
    importlib.reload(mod)


# ---------------------------------------------------------------------------
# Redaction in scanner output
# ---------------------------------------------------------------------------

def test_21_scanner_output_metadata_redacted():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "test.py").write_text("x = 1")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["metadata"].get("redacted") is True


def test_22_error_messages_sanitized(monkeypatch):
    """Ensure error messages don't leak secret content."""
    monkeypatch.setenv("SECRETS_FALLBACK_ENABLED", "false")
    import importlib
    import app.scanner.scanners.secrets as mod
    importlib.reload(mod)

    s = mod.SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "a.py").write_text("test")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("error with AKIA1234567890ABCDEF and token=secretvalue123456")
        s.runner = mock_runner
        try:
            s.scan_with_context(ctx)
        except RuntimeError as exc:
            msg = str(exc)
            assert "AKIA1234567890ABCDEF" not in msg
            assert "secretvalue123456" not in msg
    importlib.reload(mod)


def test_23_sarif_via_cat_reaches_parser():
    """SARIF written to /tmp/sarif.json inside container must be catted to stdout."""
    from app.scanner.pipeline import ScannerPipeline

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "rules": [{"id": "test-rule"}]}},
            "results": [{
                "ruleId": "test-rule",
                "level": "warning",
                "message": {"text": "API key detected"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "config.py"}, "region": {"startLine": 5}}}]
            }],
        }],
    }
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "config.py").write_text("api_key = 'fake'")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        # Simulate sh -c wrapper: stdout is SARIF from cat
        mock_runner.run.return_value = json.dumps(sarif)
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        # SARIF must have been parsed via SarifParser and reach finding pipeline
        assert data["scanner"] == "secrets"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "test-rule"
        assert data["findings"][0]["scanner"] == "secrets"
        assert data["metadata"]["execution_engine"] == PRODUCTION_ENGINE
        assert data["metadata"]["redacted"] is True
        # Verify command was sh -c with cat fallback
        cmd = mock_runner.run.call_args[1]["command"]
        assert cmd[0] == "sh" and cmd[1] == "-c"
        assert "cat /tmp/sarif.json" in cmd[2]


def test_24_clean_sarif_produces_zero_findings():
    s = SecretsScanner()
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "clean.py").write_text("x = 1\n# clean file\n")
        ctx = ScanContext(target=tmp, workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        raw = s.scan_with_context(ctx)
        data = json.loads(raw)
        assert data["findings"] == []
        assert data["assets"] == []


def test_25_no_plaintext_in_persistence_payload():
    """Simulate persistence sanitization — plaintext must not survive."""
    from app.persistence import sanitize_metadata

    fake_secret = "AKIA_FAKE_SANITIZE_TEST_123456"
    finding = {
        "scanner": "secrets",
        "title": "aws-access-key",
        "description": f"Found {fake_secret}",
        "severity": "high",
        "evidence": f"key {fake_secret}",
        "metadata": {
            "rule_id": "aws-access-key",
            "file": "config.py",
            "secret_value": fake_secret,
            "token": fake_secret,
            "redacted": True,
        },
    }
    # Scanner-level redaction (as done in _inject_provenance)
    finding["evidence"] = _redact_text(finding["evidence"])
    finding["description"] = _redact_text(finding["description"])
    # Simulate what _inject_provenance does for metadata secret keys
    for k in list(finding["metadata"].keys()):
        if any(s in k.lower() for s in ("secret", "token", "password", "key", "credential")):
            if isinstance(finding["metadata"][k], str) and len(finding["metadata"][k]) > 10:
                finding["metadata"][k] = "[REDACTED]"
    # Persistence-level sanitization drops secret-bearing keys and caps
    sanitized = sanitize_metadata(finding["metadata"])
    # Payload that would be persisted: sanitized metadata only
    persisted_payload = json.dumps({"sanitized_metadata": sanitized, "evidence": finding["evidence"]})
    assert fake_secret not in persisted_payload
    assert fake_secret not in finding["evidence"]
    assert fake_secret not in finding["description"]
    # sanitize_metadata strips secret-bearing keys
    assert "secret_value" not in sanitized
    assert "token" not in sanitized


def test_26_container_target_is_fixed_constant():
    """Ensure untrusted workspace value is never interpolated into shell."""
    s = SecretsScanner()
    # Use a workspace path that looks like injection attempt
    with tempfile.TemporaryDirectory() as tmp:
        # Create file to pass _workspace_has_files
        (Path(tmp) / "a.py").write_text("test")
        # Workspace with tricky name — scanner must not use it in command
        ctx = ScanContext(target="evil; cat /etc/passwd", workspace=tmp, project_id="p1", scan_id="s1")
        mock_runner = MagicMock()
        mock_runner.run.return_value = '{"version":"2.1.0","runs":[]}'
        s.runner = mock_runner
        s.scan_with_context(ctx)
        cmd = mock_runner.run.call_args[1]["command"]
        shell_script = cmd[2]
        assert "evil" not in shell_script
        assert "/etc/passwd" not in shell_script
        # Only fixed constants appear
        assert shell_script.count("/workspace") >= 1
        assert shell_script.count("/tmp/sarif.json") >= 1
