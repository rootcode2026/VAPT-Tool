import re
from app.services.sca.models import Dependency
from app.services.sca.parsers.base import BaseDependencyParser


# Regex for requirements line: name[extras] version_spec
# Supports: requests==2.25.0, requests>=2.25.0, requests[security]==2.25.0, etc.
REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)(?:\[([A-Za-z0-9_,.\- ]+)\])?\s*(.*)\s*$"
)


class RequirementsParser(BaseDependencyParser):
    manifest_type = "requirements.txt"
    ecosystem = "pypi"

    def parse(self, content: str) -> list[Dependency]:
        self._validate_size(content)
        deps: list[Dependency] = []
        for idx, raw_line in enumerate(content.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                # Skip comments, empty, and pip options (-r, --index-url, etc.) for S1
                if line.startswith("-"):
                    continue
                continue
            # Remove inline comment not in URL? For S1 keep simple: split on # if not in version spec
            # Handle hash checking lines (--hash) - skip
            if " --hash" in line:
                line = line.split(" --hash")[0].strip()
            # Handle environment markers ; (e.g., requests==2.25.0; python_version > '3.6')
            if ";" in line:
                line = line.split(";", 1)[0].strip()
            if not line:
                continue
            m = REQ_RE.match(line)
            if not m:
                raise ValueError(f"Malformed requirements line {idx}: {raw_line!r}")
            name = m.group(1).strip()
            extras_raw = m.group(2)
            version_spec = m.group(3).strip()
            if not name:
                raise ValueError(f"Missing package name on line {idx}: {raw_line!r}")
            name = self._sanitize_name(name)
            extras = []
            if extras_raw:
                extras = [e.strip() for e in extras_raw.split(",") if e.strip()]
            version: str | None = None
            resolved = False
            raw_version = version_spec if version_spec else None
            if version_spec:
                # Check for exact pinned == (allow === as well)
                # Extract first version after ==
                if "==" in version_spec and version_spec.strip().startswith("==") or "==" in version_spec:
                    # Find == version
                    # Use regex to extract version after ==
                    eq_m = re.search(r"==\s*([^\s,;]+)", version_spec)
                    if eq_m:
                        version = eq_m.group(1).strip()
                        # Exact version, resolved
                        resolved = True
                    else:
                        version = version_spec
                        resolved = False
                else:
                    # Range or no pin
                    version = version_spec
                    resolved = False
                    # If no version at all (e.g., "requests"), keep unresolved
                    if not version_spec.strip():
                        version = None
                        raw_version = None
            else:
                version = None
                raw_version = None
            deps.append(
                Dependency(
                    ecosystem="pypi",
                    name=name,
                    version=version,
                    manifest="requirements.txt",
                    dependency_type="runtime",
                    version_resolved=resolved,
                    extras=extras,
                    raw_version=raw_version,
                )
            )
        return deps
