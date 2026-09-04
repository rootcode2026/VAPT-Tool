import json
import os
from pathlib import Path

from app.scanner.base import BaseScanner, ScanContext
from app.scanner.docker_runner import DockerRunner, ScannerFailureError
from app.services.sca.analyzer import SCAAnalyzer

IGNORED_DIRS = {"node_modules", "venv", ".venv", ".git", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", ".cache"}
SUPPORTED_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
}

FALLBACK_ENABLED = os.getenv("SCA_FALLBACK_ENABLED", "false").lower() in ("1", "true", "yes", "on")
PRODUCTION_ENGINE = "osv-scanner"
PRODUCTION_VERSION = "1.9.2"
FALLBACK_ENGINE = "sca_analyzer"


class SCAScanner(BaseScanner):
    name = "sca"
    category = "application_security"
    family = "sca"
    description = "Software Composition Analysis — OSV SARIF with workspace"
    target_types = {"repository", "project", "directory", "path"}
    input_type = "manifest"
    requires_workspace = True
    supported_profiles = {"sca", "full"}
    output_format = "sarif"
    capabilities = {"sca", "dependency", "vulnerability", "sarif", "osv"}
    timeout = 120

    IMAGE = "vapt-sca:latest"
    FALLBACK_IMAGE = "ghcr.io/google/osv-scanner:1.9.2"

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
                f["scanner"] = "sca"
        return findings

    def scan(self, target: str) -> str:
        """Legacy scan — in-process analyzer for backward compatibility."""
        # Keep original manifest discovery logic for legacy direct string input
        if len(target.encode("utf-8")) > 5 * 1024 * 1024:
            raise ValueError("SCA target exceeds size limit")
        target_path = Path(target)
        manifests: dict[str, str] = {}
        manifest_paths: list[str] = []
        if target_path.exists() and target_path.is_dir():
            for root, dirs, files in os.walk(target_path, topdown=True):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
                for fname in files:
                    if fname not in SUPPORTED_FILES:
                        continue
                    fpath = Path(root) / fname
                    if any(part in IGNORED_DIRS for part in fpath.parts):
                        continue
                    try:
                        if fpath.stat().st_size > 2 * 1024 * 1024:
                            continue
                        content = fpath.read_text(encoding="utf-8", errors="strict")
                    except Exception:
                        continue
                    rel = str(fpath.relative_to(target_path))
                    mtype = fname
                    if mtype in manifests:
                        continue
                    manifests[mtype] = content
                    manifest_paths.append(rel)
                    if len(manifests) >= 10:
                        break
                if len(manifests) >= 10:
                    break
            if not manifests:
                result = {"scanner": "sca", "dependencies": [], "vulnerabilities": [], "findings": [], "errors": [], "metadata": {"manifests_scanned": 0, "execution_engine": FALLBACK_ENGINE, "execution_mode": "legacy"}}
                return json.dumps(result)
        else:
            try:
                parsed = json.loads(target)
                if isinstance(parsed, dict) and any(k in parsed for k in SUPPORTED_FILES):
                    for k, v in parsed.items():
                        if k in SUPPORTED_FILES and isinstance(v, str):
                            manifests[k] = v
                else:
                    manifests["package.json"] = target
            except (json.JSONDecodeError, TypeError):
                manifests["package.json"] = target
        try:
            from app.services.sca.factory import create_sca_analyzer
            analyzer = create_sca_analyzer()
            result = analyzer.analyze(manifests)
        except Exception:
            analyzer = SCAAnalyzer()
            result = analyzer.analyze(manifests)
        findings = self._inject_provenance(result.get("findings", []), FALLBACK_ENGINE, "legacy")
        result["findings"] = findings
        result["metadata"] = result.get("metadata", {})
        result["metadata"]["execution_engine"] = FALLBACK_ENGINE
        result["metadata"]["execution_mode"] = "legacy"
        return json.dumps(result, default=str)

    def scan_with_context(self, context: ScanContext) -> str:
        ws = context.workspace
        if not ws or not Path(ws).exists() or not Path(ws).is_dir():
            return json.dumps({"scanner": "sca", "assets": [], "findings": [], "errors": [], "metadata": {"workspace": ws, "reason": "no workspace", "execution_engine": "none", "execution_mode": "none"}})
        ws_path = Path(ws)
        src_root = ws_path / "src" if (ws_path / "src").is_dir() else ws_path

        # Quick check: any supported manifest?
        has_manifest = False
        try:
            for p in src_root.rglob("*"):
                if p.is_file() and p.name in SUPPORTED_FILES:
                    if any(part in IGNORED_DIRS for part in p.parts):
                        continue
                    try:
                        p.resolve().relative_to(ws_path.resolve())
                    except ValueError:
                        continue
                    has_manifest = True
                    break
        except Exception:
            has_manifest = False

        if not has_manifest:
            return json.dumps({"scanner": "sca", "assets": [], "findings": [], "errors": [], "metadata": {"workspace": ws, "reason": "no manifests", "execution_engine": PRODUCTION_ENGINE, "execution_mode": "empty", "engine_version": PRODUCTION_VERSION}})

        container_target = "/workspace/src" if (Path(ws) / "src").is_dir() else "/workspace"
        # OSV-Scanner command: scan --format sarif --output /tmp/sarif.json --recursive, then cat
        # Use shell to handle output redirection and handle exit 1 (findings) as success
        # OSV-Scanner exits 0 when no vulns, 1 when vulns found, 0-1 both success
        # Use --offline to avoid network
        command = [
            "sh", "-c",
            f"osv-scanner --format=sarif --output=/tmp/sarif.json --recursive {container_target} --offline 2>/dev/null; cat /tmp/sarif.json 2>/dev/null || cat /tmp/sarif.json || echo '{{\"version\":\"2.1.0\",\"runs\":[]}}'"
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
                        scanner="sca",
                        target=context.target,
                        volumes=volumes,
                        workspace=str(ws_path.resolve()),
                    )
                    # raw should be SARIF JSON; if empty, try to read from file
                    if not raw or not raw.strip():
                        raw = '{"version":"2.1.0","runs":[]}'
                except ScannerFailureError as e:
                    # OSV-Scanner exit 1 with findings is success if stdout is SARIF
                    if getattr(e, "exit_code", None) == 1 and e.stdout and e.stdout.strip().startswith("{") and '"runs"' in e.stdout:
                        raw = e.stdout
                    elif getattr(e, "exit_code", None) in (0, 1) and e.stdout and '"runs"' in e.stdout:
                        raw = e.stdout
                    else:
                        raise
                # Validate SARIF
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict) and "runs" in parsed:
                        from app.scanner.parsers.sarif_parser import SarifParser
                        sarif_parser = SarifParser()
                        parsed_result = sarif_parser.parse(raw)
                        # Inject provenance and package context
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
                if not FALLBACK_ENABLED:
                    raise
                # Fallback to local analyzer
                try:
                    # Use legacy manifest discovery on workspace
                    target_path = Path(ws)
                    manifests: dict[str, str] = {}
                    for root, dirs, files in os.walk(target_path, topdown=True):
                        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
                        for fname in files:
                            if fname not in SUPPORTED_FILES:
                                continue
                            fpath = Path(root) / fname
                            if any(part in IGNORED_DIRS for part in fpath.parts):
                                continue
                            try:
                                if fpath.stat().st_size > 2 * 1024 * 1024:
                                    continue
                                content = fpath.read_text(encoding="utf-8", errors="strict")
                            except Exception:
                                continue
                            if fname not in manifests:
                                manifests[fname] = content
                                if len(manifests) >= 10:
                                    break
                        if len(manifests) >= 10:
                            break
                    from app.services.sca.factory import create_sca_analyzer
                    try:
                        analyzer = create_sca_analyzer()
                        result = analyzer.analyze(manifests)
                    except Exception:
                        analyzer = SCAAnalyzer()
                        result = analyzer.analyze(manifests)
                    findings = self._inject_provenance(result.get("findings", []), FALLBACK_ENGINE, "fallback")
                    result["findings"] = findings
                    result["metadata"] = result.get("metadata", {})
                    result["metadata"]["execution_engine"] = FALLBACK_ENGINE
                    result["metadata"]["execution_mode"] = "fallback"
                    result["metadata"]["fallback_reason"] = str(exc)[:500]
                    return json.dumps(result, default=str)
                except Exception:
                    raise exc
        if last_exc:
            raise last_exc
        if FALLBACK_ENABLED:
            # Final fallback
            from app.services.sca.factory import create_sca_analyzer
            try:
                analyzer = create_sca_analyzer()
                result = analyzer.analyze({})
            except Exception:
                analyzer = SCAAnalyzer()
                result = analyzer.analyze({})
            result["findings"] = self._inject_provenance(result.get("findings", []), FALLBACK_ENGINE, "fallback")
            result["metadata"] = result.get("metadata", {})
            result["metadata"]["execution_engine"] = FALLBACK_ENGINE
            result["metadata"]["execution_mode"] = "fallback"
            return json.dumps(result, default=str)
        raise RuntimeError("SCA scanner failed and fallback is disabled")
