try:
    import tomllib
except ImportError:
    import tomli as tomllib

from app.services.sca.models import Dependency
from app.services.sca.parsers.base import BaseDependencyParser


class PoetryLockParser(BaseDependencyParser):
    manifest_type = "poetry.lock"
    ecosystem = "pypi"

    def parse(self, content: str) -> list[Dependency]:
        self._validate_size(content)
        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise ValueError(f"Invalid TOML in poetry.lock: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("poetry.lock must be a TOML table")

        packages = data.get("package")
        if packages is None:
            # Some poetry.lock use [[package]] => list
            raise ValueError("Unsupported poetry.lock structure: missing 'package'")

        if not isinstance(packages, list):
            raise ValueError("'package' in poetry.lock must be a list")

        deps: list[Dependency] = []
        seen: set[str] = set()
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            name = self._sanitize_name(str(name))
            version = str(version).strip()
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            deps.append(
                Dependency(
                    ecosystem="pypi",
                    name=name,
                    version=version,
                    manifest="poetry.lock",
                    dependency_type="runtime",
                    version_resolved=True,
                    raw_version=version,
                )
            )
        return deps
