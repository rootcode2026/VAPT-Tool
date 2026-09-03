try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib

import re
from app.services.sca.models import Dependency
from app.services.sca.parsers.base import BaseDependencyParser


def _parse_dep_string(dep_str: str) -> tuple[str, str | None]:
    dep_str = dep_str.strip()
    if not dep_str:
        raise ValueError("Empty dependency string")
    # Handle extras and version: e.g., "requests[security]==2.25.0", "requests >=2.25.0"
    # Extract name
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*(.*)\s*$", dep_str)
    if not m:
        raise ValueError(f"Malformed dependency: {dep_str!r}")
    name = m.group(1).strip()
    version_spec = m.group(2).strip() if m.group(2) else None
    if version_spec == "":
        version_spec = None
    return name, version_spec


class PyprojectParser(BaseDependencyParser):
    manifest_type = "pyproject.toml"
    ecosystem = "pypi"

    def parse(self, content: str) -> list[Dependency]:
        self._validate_size(content)
        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise ValueError(f"Invalid TOML in pyproject.toml: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("pyproject.toml must be a TOML table")

        deps: list[Dependency] = []

        # [project] dependencies = ["requests==2.25.0", ...]
        project = data.get("project")
        if isinstance(project, dict):
            dependencies = project.get("dependencies")
            if dependencies is not None:
                if not isinstance(dependencies, list):
                    raise ValueError("[project] dependencies must be a list")
                for dep_str in dependencies:
                    if not isinstance(dep_str, str):
                        raise ValueError(f"Dependency must be string: {dep_str!r}")
                    name, version_spec = _parse_dep_string(dep_str)
                    name = self._sanitize_name(name)
                    version = version_spec
                    resolved = False
                    if version and "==" in version:
                        # Try to extract exact version
                        m = re.search(r"==\s*([^\s,;]+)", version)
                        if m:
                            version = m.group(1).strip()
                            resolved = True
                    deps.append(
                        Dependency(
                            ecosystem="pypi",
                            name=name,
                            version=version,
                            manifest="pyproject.toml",
                            dependency_type="runtime",
                            version_resolved=resolved,
                            raw_version=version_spec,
                        )
                    )
            # Optional dependencies: [project.optional-dependencies]
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict):
                for group, dep_list in optional.items():
                    if not isinstance(dep_list, list):
                        continue
                    for dep_str in dep_list:
                        if not isinstance(dep_str, str):
                            continue
                        name, version_spec = _parse_dep_string(dep_str)
                        name = self._sanitize_name(name)
                        version = version_spec
                        resolved = False
                        if version and "==" in version:
                            m = re.search(r"==\s*([^\s,;]+)", version)
                            if m:
                                version = m.group(1).strip()
                                resolved = True
                        deps.append(
                            Dependency(
                                ecosystem="pypi",
                                name=name,
                                version=version,
                                manifest="pyproject.toml",
                                dependency_type="optional",
                                version_resolved=resolved,
                                raw_version=version_spec,
                            )
                        )

        # Also handle [tool.poetry.dependencies] as fallback (poetry pyproject)
        tool = data.get("tool")
        if isinstance(tool, dict):
            poetry = tool.get("poetry")
            if isinstance(poetry, dict):
                poetry_deps = poetry.get("dependencies")
                if isinstance(poetry_deps, dict):
                    for name, spec in poetry_deps.items():
                        if name == "python":
                            continue
                        name = self._sanitize_name(str(name))
                        version_spec = None
                        if isinstance(spec, str):
                            version_spec = spec.strip()
                        elif isinstance(spec, dict):
                            version_spec = spec.get("version")
                            if version_spec:
                                version_spec = str(version_spec).strip()
                        version = version_spec
                        resolved = False
                        if version and version not in ("*", "") and "==" not in version and not any(c in version for c in "^~><"):
                            # Poetry exact version like "2.25.0"
                            version = version.strip()
                            resolved = True
                        deps.append(
                            Dependency(
                                ecosystem="pypi",
                                name=name,
                                version=version,
                                manifest="pyproject.toml",
                                dependency_type="runtime",
                                version_resolved=resolved,
                                raw_version=version_spec,
                            )
                        )

        return deps
