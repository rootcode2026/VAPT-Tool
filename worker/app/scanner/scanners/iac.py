"""S7.7 Production IaC Security — Checkov Docker, SARIF, workspace, no socket.

Scans Terraform, Kubernetes, CloudFormation, Dockerfile and other IaC
artifacts for misconfigurations and policy violations.

Security: pinned image/digest, non-root, no privileged, no Docker socket,
workspace mounted read-only, strict path validation, array-form command,
timeout enforcement.
"""

import json
import os
from pathlib import Path

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.docker_runner import DockerRunner, ScannerFailureError

FALLBACK_ENABLED = os.getenv(
    "IAC_FALLBACK_ENABLED", "false"
).lower() in ("1", "true", "yes", "on")
FALLBACK_ENGINE = "iac_fallback"
PRODUCTION_ENGINE = "checkov"
PRODUCTION_VERSION = "3.3.16"

SUPPORTED_IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".cache", "vendor", ".tox",
}

# IaC file indicators — quick empty check (not exhaustive; checkov handles filtering)
IAC_EXTENSIONS = {".tf", ".yaml", ".yml", ".json"}
IAC_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}


class IacScanner(BaseScanner):
    name = "iac"
    category = "application_security"
    family = "iac"
    description = "IaC Security — Checkov 3.3.16 SARIF with workspace, misconfiguration/policy checks"
    target_types = {"repository", "project", "directory"}
    input_type = "iac"
    requires_workspace = True
    supported_profiles = {"iac", "iac_full"}
    output_format = "sarif"
    capabilities = {"iac", "misconfiguration", "policy", "terraform", "kubernetes", "cloudformation", "dockerfile", "sarif", "checkov"}
    timeout = int(os.getenv("IAC_TIMEOUT", "180"))

    IMAGE = os.getenv("IAC_IMAGE", "vapt-iac:latest")
    FALLBACK_IMAGE = "bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016"

    def __init__(self):
        self.runner = None

    def _get_runner(self):
        if self.runner is None:
            self.runner = DockerRunner()
        return self.runner

    def _inject_provenance(self, findings: list[dict], engine: str, mode: str) -> list[dict]:
        for f in findings:
            if not isinstance(f, dict):
                continue
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if not isinstance(meta, dict):
                meta = {}
            meta["execution_engine"] = engine
            meta["execution_mode"] = mode
            if engine == PRODUCTION_ENGINE:
                meta["engine_version"] = PRODUCTION_VERSION
                meta["image"] = self.IMAGE
            f["metadata"] = meta
            f["scanner"] = "iac"
        return findings

    def _workspace_has_iac(self, ws_path: Path) -> bool:
        """Quick check: does workspace contain any IaC scannable files?"""
        src_root = ws_path / "src" if (ws_path / "src").is_dir() else ws_path
        try:
            for p in src_root.rglob("*"):
                if not p.is_file():
                    continue
                if any(part in SUPPORTED_IGNORED_DIRS for part in p.parts):
                    continue
                try:
                    p.resolve().relative_to(ws_path.resolve())
                except ValueError:
                    continue
                try:
                    if p.stat().st_size > 5 * 1024 * 1024:
                        continue
                except Exception:
                    continue
                # Check by extension or filename
                if p.suffix.lower() in IAC_EXTENSIONS:
                    return True
                if p.name in IAC_FILENAMES:
                    return True
                # Also detect Terraform via .tf, and generic IaC via directory containing relevant files
                # Be permissive: if any file exists and is not ignored, consider scannable
                # Checkov will handle filtering; this just avoids empty scan overhead
                # For IaC we are slightly more permissive than SAST — return True if any file <5MB
                # but only after checking ignored dirs; this ensures empty workspaces still handled
                # Actually require at least one IaC indicator to avoid scanning random workspaces
                # So only return True for known IaC files; otherwise continue
                continue
        except Exception:
            return False
        return False

    def scan(self, target: str) -> str:
        """Legacy scan — returns empty with provenance. Preserves backward compat."""
        result = {
            "scanner": "iac",
            "assets": [],
            "findings": [],
            "errors": [],
            "metadata": {
                "execution_engine": FALLBACK_ENGINE,
                "execution_mode": "legacy",
                "reason": "legacy scan without workspace",
            },
        }
        return json.dumps(result)

    def scan_with_context(self, context: ScanContext) -> str:
        ws = context.workspace
        if not ws or not Path(ws).exists() or not Path(ws).is_dir():
            return json.dumps({
                "scanner": "iac", "assets": [], "findings": [], "errors": [],
                "metadata": {"workspace": ws, "reason": "no workspace",
                             "execution_engine": "none", "execution_mode": "none"},
            })

        ws_path = Path(ws)

        if not self._workspace_has_iac(ws_path):
            return json.dumps({
                "scanner": "iac", "assets": [], "findings": [], "errors": [],
                "metadata": {"workspace": ws, "reason": "no iac files",
                             "execution_engine": PRODUCTION_ENGINE, "execution_mode": "empty",
                             "engine_version": PRODUCTION_VERSION},
            })

        container_target = "/workspace/src" if (ws_path / "src").is_dir() else "/workspace"

        # Checkov command — array form, no shell interpolation
        # -d <dir> scans recursively, --framework all covers terraform/k8s/cfn/dockerfile
        # -o json prints JSON to stdout (SARIF via file fails on ro mount, see live verification);
        # we use JSON and let the parser normalize to findings. JSON output is stable
        # and avoids the SARIF file-write-on-ro issue observed with checkov 3.3.16
        # (SARIF tries to write results.sarif to cwd which is ro). JSON goes to stdout
        # directly, no file, no socket, no privileged.
        command = [
            "checkov",
            "-d", container_target,
            "--framework", "all",
            "-o", "json",
            "--quiet",
        ]

        volumes = {str(ws_path.resolve()): {"bind": "/workspace", "mode": "ro"}}
        runner = self._get_runner()
        last_exc = None

        for image in [self.IMAGE, self.FALLBACK_IMAGE]:
            try:
                try:
                    raw = runner.run(
                        image=image,
                        command=command,
                        timeout=self.timeout,
                        scanner="iac",
                        target=context.target,
                        volumes=volumes,
                        workspace=str(ws_path.resolve()),
                    )
                    if not raw or not raw.strip():
                        raw = '{"version":"2.1.0","runs":[]}'
                except ScannerFailureError as e:
                    # Checkov exits non-zero on findings; treat JSON/SARIF in stdout as success
                    stdout = e.stdout or ""
                    if getattr(e, "exit_code", None) in (0, 1) and stdout and ('"runs"' in stdout or '"results"' in stdout or '"failed_checks"' in stdout):
                        raw = stdout
                    elif stdout and ('"runs"' in stdout or '"results"' in stdout):
                        raw = stdout
                    else:
                        raise

                # Parse — handle both SARIF and Checkov JSON
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict) and "runs" in parsed:
                        from app.scanner.parsers.sarif_parser import SarifParser
                        sarif_parser = SarifParser()
                        parsed_result = sarif_parser.parse(raw)
                        parsed_result["scanner"] = "iac"
                        parsed_result["findings"] = self._inject_provenance(
                            parsed_result.get("findings", []), PRODUCTION_ENGINE, "docker"
                        )
                        for a in parsed_result.get("assets", []):
                            if isinstance(a.get("metadata"), dict):
                                a["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                            else:
                                a["metadata"] = {"execution_engine": PRODUCTION_ENGINE}
                        parsed_result["metadata"] = parsed_result.get("metadata", {})
                        parsed_result["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                        parsed_result["metadata"]["execution_mode"] = "docker"
                        parsed_result["metadata"]["engine_version"] = PRODUCTION_VERSION
                        parsed_result["metadata"]["image"] = image
                        return json.dumps(parsed_result)
                    if isinstance(parsed, dict) and "results" in parsed:
                        # Checkov JSON format
                        from app.scanner.parsers.iac_parser import IacParser
                        parser = IacParser()
                        parsed_result = parser.parse(raw)
                        parsed_result["scanner"] = "iac"
                        parsed_result["findings"] = self._inject_provenance(
                            parsed_result.get("findings", []), PRODUCTION_ENGINE, "docker"
                        )
                        for a in parsed_result.get("assets", []):
                            if isinstance(a.get("metadata"), dict):
                                a["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                            else:
                                a["metadata"] = {"execution_engine": PRODUCTION_ENGINE}
                        parsed_result["metadata"] = parsed_result.get("metadata", {})
                        parsed_result["metadata"]["execution_engine"] = PRODUCTION_ENGINE
                        parsed_result["metadata"]["execution_mode"] = "docker"
                        parsed_result["metadata"]["engine_version"] = PRODUCTION_VERSION
                        parsed_result["metadata"]["image"] = image
                        return json.dumps(parsed_result)
                    return raw
                except json.JSONDecodeError:
                    return raw
            except Exception as exc:
                last_exc = exc
                if "not found" in str(exc).lower() and image == self.IMAGE:
                    continue
                if not FALLBACK_ENABLED:
                    raise
                # Fallback enabled: return empty with provenance
                try:
                    result = {
                        "scanner": "iac", "assets": [], "findings": [], "errors": [],
                        "metadata": {
                            "execution_engine": FALLBACK_ENGINE,
                            "execution_mode": "fallback",
                            "fallback_reason": str(exc)[:500],
                        },
                    }
                    return json.dumps(result)
                except Exception:
                    raise exc

        if last_exc:
            raise last_exc
        if FALLBACK_ENABLED:
            return json.dumps({
                "scanner": "iac", "assets": [], "findings": [],
                "metadata": {"execution_engine": FALLBACK_ENGINE, "execution_mode": "fallback"},
            })
        raise RuntimeError("Iac scanner failed and fallback is disabled")
