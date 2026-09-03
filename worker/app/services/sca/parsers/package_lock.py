import json
from app.services.sca.models import Dependency
from app.services.sca.parsers.base import BaseDependencyParser


class PackageLockParser(BaseDependencyParser):
    manifest_type = "package-lock.json"
    ecosystem = "npm"

    def parse(self, content: str) -> list[Dependency]:
        self._validate_size(content)
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in package-lock.json: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("package-lock.json must be a JSON object")

        deps: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        # v1: dependencies field, v2/v3: packages field
        # Try packages first (npm 7+)
        packages = data.get("packages")
        if isinstance(packages, dict):
            for pkg_path, info in packages.items():
                if not pkg_path or pkg_path == "":
                    continue  # root
                # pkg_path like "node_modules/lodash" or "node_modules/@babel/core"
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if not version:
                    continue
                # Extract name from path: last segment, handling scoped
                # e.g., node_modules/@babel/core -> @babel/core
                parts = pkg_path.split("node_modules/")
                last = parts[-1] if parts else pkg_path
                name = last.strip()
                if not name:
                    continue
                # Deduplicate by name+version
                key = (name.lower(), str(version))
                if key in seen:
                    continue
                seen.add(key)
                deps.append(
                    Dependency(
                        ecosystem="npm",
                        name=self._sanitize_name(name),
                        version=str(version).strip(),
                        manifest="package-lock.json",
                        dependency_type="runtime",
                        version_resolved=True,
                        raw_version=str(version).strip(),
                    )
                )
            return deps

        # v1 fallback: dependencies
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            for name, info in dependencies.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if not version:
                    continue
                key = (name.lower(), str(version))
                if key in seen:
                    continue
                seen.add(key)
                deps.append(
                    Dependency(
                        ecosystem="npm",
                        name=self._sanitize_name(str(name)),
                        version=str(version).strip(),
                        manifest="package-lock.json",
                        dependency_type="runtime",
                        version_resolved=True,
                        raw_version=str(version).strip(),
                    )
                )
            return deps

        # If neither structure found, treat as unsupported
        if not deps:
            # Check if file has no packages but is valid lockfile with lockfileVersion
            if "lockfileVersion" in data and not packages and not dependencies:
                return []
            raise ValueError("Unsupported package-lock.json structure: missing 'packages' or 'dependencies'")
        return deps
