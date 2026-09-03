import json
from app.services.sca.models import Dependency
from app.services.sca.parsers.base import BaseDependencyParser


class PackageJsonParser(BaseDependencyParser):
    manifest_type = "package.json"
    ecosystem = "npm"

    def parse(self, content: str) -> list[Dependency]:
        self._validate_size(content)
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in package.json: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("package.json must be a JSON object")

        deps: list[Dependency] = []
        for dep_type, manifest_field in [
            ("runtime", "dependencies"),
            ("optional", "optionalDependencies"),
            ("development", "devDependencies"),
        ]:
            section = data.get(manifest_field)
            if section is None:
                continue
            if not isinstance(section, dict):
                raise ValueError(f"Field {manifest_field} must be an object")
            for name, ver in section.items():
                name = self._sanitize_name(str(name))
                raw = str(ver).strip() if ver is not None else ""
                # Do not resolve range; keep as is, unresolved unless exact version
                # Check if version is exact (e.g., 4.17.20 without ^ ~ etc)
                version = raw if raw else None
                # Determine resolved: exact semver without range prefix
                resolved = False
                if version and version[0] not in "^~><=*":
                    # Also check if it's exact like 4.17.20
                    resolved = True
                deps.append(
                    Dependency(
                        ecosystem="npm",
                        name=name,
                        version=version,
                        manifest="package.json",
                        dependency_type=dep_type,
                        version_resolved=resolved,
                        raw_version=raw,
                    )
                )
        return deps
