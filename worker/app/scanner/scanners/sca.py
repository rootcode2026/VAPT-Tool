import json
import os
from pathlib import Path

from app.scanner.base import BaseScanner
from app.services.sca.analyzer import SCAAnalyzer
from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider

# For S2, default to fixture provider for determinism; OSV can be injected via analyzer if needed
# To use OSV, set SCA_PROVIDER=osv or mock in tests

IGNORED_DIRS = {"node_modules", "venv", ".venv", ".git", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", ".cache"}
IGNORED_PARTS = {".git", "node_modules", "venv", "__pycache__"}

SUPPORTED_FILES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
}

MAX_MANIFESTS = 10
MAX_FILE_SIZE = 2 * 1024 * 1024  # reuse analyzer limit


class SCAScanner(BaseScanner):
    name = "sca"
    category = "application_security"
    description = "Software Composition Analysis — dependency vulnerability detection"
    target_types = {"repository", "project", "directory", "path"}
    input_type = "manifest"
    output_format = "json"
    capabilities = {"sca", "dependency", "vulnerability"}
    timeout = 60

    def scan(self, target: str) -> str:
        """
        Discover manifests recursively under target directory and analyze.

        Target is expected to be a filesystem path (project directory).
        For backward compatibility, if target is not a valid directory, treat it as manifest content.
        """
        # Input size guard
        if len(target.encode("utf-8")) > 5 * 1024 * 1024:
            raise ValueError("SCA target exceeds size limit")

        # Determine if target is a directory path
        target_path = Path(target)
        manifests: dict[str, str] = {}
        manifest_paths: list[str] = []

        if target_path.exists() and target_path.is_dir():
            # Recursive discovery
            for root, dirs, files in os.walk(target_path, topdown=True):
                # Modify dirs in-place to skip ignored
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
                # Also skip hidden cache directories
                dirs[:] = [d for d in dirs if d not in {"__pycache__", ".cache"}]
                # Prevent descending into ignored parts
                # os.walk already handles topdown, so this is sufficient
                for fname in files:
                    if fname not in SUPPORTED_FILES:
                        continue
                    fpath = Path(root) / fname
                    # Skip if any part is ignored
                    if any(part in IGNORED_DIRS for part in fpath.parts):
                        continue
                    if any(part.startswith(".") and part in {".git", ".cache"} for part in fpath.parts):
                        continue
                    # Check file size
                    try:
                        if fpath.stat().st_size > MAX_FILE_SIZE:
                            continue
                        content = fpath.read_text(encoding="utf-8", errors="strict")
                    except Exception as e:
                        # Malformed or unreadable -> will be recorded as error in analyzer
                        # For now, skip and let analyzer handle via errors? But we need to surface error
                        # Instead, include as manifest with content that will fail parsing and be recorded
                        try:
                            content = fpath.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            continue
                    # Use manifest type as key, but need to handle duplicate names in different directories
                    # For S2, use file path as manifest identifier, but analyzer expects manifest_type
                    # We'll use the filename as key and deduplicate by content? For now, use relative path
                    rel = str(fpath.relative_to(target_path))
                    # Use manifest type based on filename
                    mtype = fname
                    # If multiple same manifest types in different dirs, we need to handle
                    # For now, if same mtype already exists, keep first and record duplicate as separate?
                    # Simpler: use mtype as key, but if duplicate, merge? For S2 we limit to 10 manifests total
                    if mtype in manifests:
                        # Duplicate manifest type in different directory - keep count but avoid overwrite
                        # Use path as key with type prefix
                        key = f"{rel}:{mtype}"
                        # But analyzer expects manifest_type, so we need to keep type
                        # We'll store with original type but ensure uniqueness via loop
                        # For simplicity, if duplicate, skip second occurrence (deduplicate)
                        continue
                    manifests[mtype] = content
                    manifest_paths.append(rel)
                    if len(manifests) >= MAX_MANIFESTS:
                        break
                if len(manifests) >= MAX_MANIFESTS:
                    break
            if not manifests:
                # No manifests found -> return empty result
                result = {
                    "scanner": "sca",
                    "dependencies": [],
                    "vulnerabilities": [],
                    "findings": [],
                    "errors": [],
                    "metadata": {
                        "manifests_scanned": 0,
                        "dependencies_total": 0,
                        "vulnerable_dependencies": 0,
                        "provider": "fixture",
                        "provider_errors": [],
                        "manifest_paths": [],
                    },
                }
                return json.dumps(result)
        else:
            # Try to parse target as JSON manifest map
            try:
                parsed = json.loads(target)
                if isinstance(parsed, dict) and any(k in parsed for k in SUPPORTED_FILES):
                    for k, v in parsed.items():
                        if k in SUPPORTED_FILES and isinstance(v, str):
                            if len(v.encode("utf-8")) <= MAX_FILE_SIZE:
                                manifests[k] = v
                elif isinstance(parsed, dict) and "content" in parsed and "manifest_type" in parsed:
                    manifests[parsed["manifest_type"]] = parsed["content"]
                else:
                    # Treat entire target as package.json content
                    manifests["package.json"] = target
            except (json.JSONDecodeError, TypeError):
                # Treat as raw manifest content (assume package.json)
                manifests["package.json"] = target

        # Invoke SCAAnalyzer via factory (production -> osv, test/dev -> fixture)
        # Explicit injection still works: SCAAnalyzer(provider=...)
        try:
            from app.services.sca.factory import create_sca_analyzer

            analyzer = create_sca_analyzer()
            result = analyzer.analyze(manifests)
        except Exception as e:
            # Fallback to direct analyzer if factory unavailable
            try:
                analyzer = SCAAnalyzer()
                result = analyzer.analyze(manifests)
            except Exception as inner:
                raise ValueError(f"SCA analysis failed: {inner}") from inner

        # Build scanner output compatible with pipeline: include metadata for observability
        output = {
            "scanner": "sca",
            "dependencies": result.get("dependencies", []),
            "vulnerabilities": result.get("vulnerabilities", []),
            "findings": result.get("findings", []),
            "errors": result.get("errors", []),
            "metadata": {
                "manifests_scanned": len(result.get("dependencies", [])),
                "dependencies_total": len(result.get("dependencies", [])),
                "vulnerable_dependencies": len({(v["ecosystem"], v["package_name"], v["installed_version"]) for v in result.get("vulnerabilities", [])}),
                "provider": "fixture",
                "provider_errors": [e for e in result.get("errors", []) if e.get("provider_error")],
                "manifest_paths": manifest_paths,
                "manifest_types": list(manifests.keys()),
            },
        }
        return json.dumps(output, default=str)
