import json
import os
from pathlib import Path

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.docker_runner import DockerRunner, ScannerFailureError
from app.services.sast.analyzer import SASTAnalyzer

# Supported extensions for quick empty check
SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}

# Fallback policy — production must not silently downgrade Semgrep to local analyzer
FALLBACK_ENABLED = os.getenv("SAST_FALLBACK_ENABLED", "false").lower() in ("1", "true", "yes", "on")
FALLBACK_ENGINE = "sast_analyzer"
PRODUCTION_ENGINE = "semgrep"
PRODUCTION_VERSION = "1.75.0"


class SASTScanner(BaseScanner):
    name = "sast"
    category = "application_security"
    family = "sast"
    description = "Static Application Security Testing for Python source code — Semgrep SARIF with workspace"
    target_types = {"repository", "project", "directory"}
    input_type = "source_code"
    requires_workspace = True
    supported_profiles = {"sast", "full"}
    output_format = "sarif"
    capabilities = {"sast", "static_analysis", "python", "javascript", "typescript", "java", "go", "sarif"}
    timeout = 120

    IMAGE = "vapt-sast:latest"
    FALLBACK_IMAGE = "returntocorp/semgrep:1.75.0"

    def __init__(self):
        self.runner = None

    def _get_runner(self):
        if self.runner is None:
            self.runner = DockerRunner()
        return self.runner

    def _inject_provenance(self, findings: list[dict], engine: str, mode: str) -> list[dict]:
        for f in findings:
            if isinstance(f, dict):
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                if not isinstance(meta, dict):
                    meta = {}
                meta["execution_engine"] = engine
                meta["execution_mode"] = mode
                if engine == PRODUCTION_ENGINE:
                    meta["engine_version"] = PRODUCTION_VERSION
                    meta["image"] = self.IMAGE
                f["metadata"] = meta
                # Also ensure scanner field remains sast
                f["scanner"] = "sast"
        return findings

    def scan(self, target: str) -> str:
        """Legacy scan — in-process analyzer for backward compatibility.
        Explicitly marks provenance as local analyzer, not Semgrep.
        """
        analyzer = SASTAnalyzer()
        result = analyzer.analyze(target)
        # Inject provenance for legacy path
        findings = self._inject_provenance(result.get("findings", []), FALLBACK_ENGINE, "legacy")
        result["findings"] = findings
        result["metadata"] = result.get("metadata", {})
        result["metadata"]["execution_engine"] = FALLBACK_ENGINE
        result["metadata"]["execution_mode"] = "legacy"
        return json.dumps(result)

    def scan_with_context(self, context: ScanContext) -> str:
        ws = context.workspace
        # Validate workspace exists and is inside allowed base
        if not ws or not Path(ws).exists() or not Path(ws).is_dir():
            # No valid workspace — graceful empty result (do not fail scan)
            return json.dumps({
                "scanner": "sast",
                "assets": [],
                "findings": [],
                "errors": [],
                "metadata": {"workspace": ws, "reason": "no workspace", "execution_engine": "none", "execution_mode": "none"}
            })

        ws_path = Path(ws)
        src_root = ws_path / "src" if (ws_path / "src").is_dir() else ws_path

        # Quick empty check: if no supported files, return empty success (avoid expensive scan)
        has_files = False
        try:
            for p in src_root.rglob("*"):
                if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
                    if any(part in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"} for part in p.parts):
                        continue
                    try:
                        p.resolve().relative_to(ws_path.resolve())
                    except ValueError:
                        continue
                    has_files = True
                    break
        except Exception:
            has_files = False

        if not has_files:
            return json.dumps({
                "scanner": "sast",
                "assets": [],
                "findings": [],
                "errors": [],
                "metadata": {"workspace": ws, "reason": "no source files", "execution_engine": PRODUCTION_ENGINE, "execution_mode": "empty", "engine_version": PRODUCTION_VERSION}
            })

        container_target = "/workspace/src" if (Path(ws) / "src").is_dir() else "/workspace"
        # Use p/security-audit for deterministic offline rules (no network, no metrics)
        command = [
            "semgrep",
            "--config=p/security-audit",
            "--sarif",
            "--error",
            "--metrics", "off",
            "--timeout", "60",
            container_target,
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
                        scanner="sast",
                        target=context.target,
                        volumes=volumes,
                        workspace=str(ws_path.resolve()),
                    )
                except ScannerFailureError as e:
                    if getattr(e, "exit_code", None) == 1 and e.stdout and e.stdout.strip().startswith("{"):
                        raw = e.stdout
                    else:
                        raise
                # Validate SARIF
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict) and "runs" in parsed:
                        # Inject provenance into SARIF via post-parse
                        from app.scanner.parsers.sarif_parser import SarifParser
                        sarif_parser = SarifParser()
                        parsed_result = sarif_parser.parse(raw)
                        # Inject provenance into findings/assets
                        parsed_result["findings"] = self._inject_provenance(parsed_result.get("findings", []), PRODUCTION_ENGINE, "docker")
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
                # If fallback disabled, do NOT silently downgrade — fail explicitly
                if not FALLBACK_ENABLED:
                    # Preserve original error, do not fallback
                    raise
                # Fallback enabled: use local analyzer but mark provenance clearly
                try:
                    analyzer = SASTAnalyzer()
                    result = analyzer.analyze(str(ws_path))
                    findings = self._inject_provenance(result.get("findings", []), FALLBACK_ENGINE, "fallback")
                    result["findings"] = findings
                    result["metadata"] = result.get("metadata", {})
                    result["metadata"]["execution_engine"] = FALLBACK_ENGINE
                    result["metadata"]["execution_mode"] = "fallback"
                    result["metadata"]["fallback_reason"] = str(exc)[:500]
                    return json.dumps(result)
                except Exception:
                    raise exc
        # If all images fail and fallback disabled, raise last error
        if last_exc:
            raise last_exc
        # Fallback disabled path should have raised above; if we reach here, fallback is enabled
        if FALLBACK_ENABLED:
            analyzer = SASTAnalyzer()
            result = analyzer.analyze(str(ws_path))
            result["findings"] = self._inject_provenance(result.get("findings", []), FALLBACK_ENGINE, "fallback")
            result["metadata"] = result.get("metadata", {})
            result["metadata"]["execution_engine"] = FALLBACK_ENGINE
            result["metadata"]["execution_mode"] = "fallback"
            return json.dumps(result)
        raise RuntimeError("Sast scanner failed and fallback is disabled")
