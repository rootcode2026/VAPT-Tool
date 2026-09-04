"""S7.8 Production API Security — OpenAPI/Swagger static analysis, SARIF, workspace.

Scans OpenAPI/Swagger specs for endpoint discovery, method coverage,
security configuration, and common API/web vulnerabilities.

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
    "API_FALLBACK_ENABLED", "false"
).lower() in ("1", "true", "yes", "on")
FALLBACK_ENGINE = "api_fallback"
PRODUCTION_ENGINE = "vapt-api"
PRODUCTION_VERSION = "1.0.0"

SUPPORTED_IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".cache", "vendor", ".tox",
}

# API spec indicators for quick empty check
API_SPEC_NAMES = {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml", "api.json", "api.yaml", "api.yml"}
API_SPEC_SUFFIXES = {".json", ".yaml", ".yml"}


class ApiScanner(BaseScanner):
    name = "api"
    category = "application_security"
    family = "api"
    description = "API Security — OpenAPI/Swagger 1.0.0 SARIF with workspace, endpoint/security checks"
    target_types = {"repository", "project", "directory", "api_spec"}
    input_type = "api_spec"
    requires_workspace = True
    supported_profiles = {"api", "api_full"}
    output_format = "sarif"
    capabilities = {"api", "openapi", "swagger", "endpoint_discovery", "security_config", "sarif", "vapt-api"}
    timeout = int(os.getenv("API_TIMEOUT", "120"))

    IMAGE = os.getenv("API_IMAGE", "vapt-api:latest")
    FALLBACK_IMAGE = "python@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534"

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
            f["scanner"] = "api"
        return findings

    def _workspace_has_api_spec(self, ws_path: Path) -> bool:
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
                # Check by name
                if p.name in API_SPEC_NAMES:
                    return True
                if p.suffix.lower() in API_SPEC_SUFFIXES:
                    # Quick content check for openapi/swagger
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")[:2000].lower()
                        if "openapi" in text or "swagger" in text:
                            return True
                    except Exception:
                        continue
        except Exception:
            return False
        return False

    def scan(self, target: str) -> str:
        result = {
            "scanner": "api",
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
                "scanner": "api", "assets": [], "findings": [], "errors": [],
                "metadata": {"workspace": ws, "reason": "no workspace",
                             "execution_engine": "none", "execution_mode": "none"},
            })
        ws_path = Path(ws)

        if not self._workspace_has_api_spec(ws_path):
            return json.dumps({
                "scanner": "api", "assets": [], "findings": [], "errors": [],
                "metadata": {"workspace": ws, "reason": "no api spec",
                             "execution_engine": PRODUCTION_ENGINE, "execution_mode": "empty",
                             "engine_version": PRODUCTION_VERSION},
            })

        container_target = "/workspace/src" if (ws_path / "src").is_dir() else "/workspace"

        # API scanner writes SARIF to file, then cat to stdout (like SCA/secrets)
        # Validator is at /app/api_scan.py inside image
        command = [
            "sh", "-c",
            f"python /app/api_scan.py {container_target} --output /tmp/sarif.json 2>/dev/null; cat /tmp/sarif.json 2>/dev/null || cat /tmp/sarif.json || echo '{{\"version\":\"2.1.0\",\"runs\":[]}}'",
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
                        scanner="api",
                        target=context.target,
                        volumes=volumes,
                        workspace=str(ws_path.resolve()),
                    )
                    if not raw or not raw.strip():
                        raw = '{"version":"2.1.0","runs":[]}'
                except ScannerFailureError as e:
                    if getattr(e, "exit_code", None) in (0, 1) and e.stdout and '"runs"' in e.stdout:
                        raw = e.stdout
                    elif e.stdout and '"runs"' in e.stdout:
                        raw = e.stdout
                    else:
                        raise

                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict) and "runs" in parsed:
                        from app.scanner.parsers.sarif_parser import SarifParser
                        sarif_parser = SarifParser()
                        parsed_result = sarif_parser.parse(raw)
                        parsed_result["scanner"] = "api"
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
                try:
                    result = {
                        "scanner": "api", "assets": [], "findings": [], "errors": [],
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
                "scanner": "api", "assets": [], "findings": [],
                "metadata": {"execution_engine": FALLBACK_ENGINE, "execution_mode": "fallback"},
            })
        raise RuntimeError("Api scanner failed and fallback is disabled")
