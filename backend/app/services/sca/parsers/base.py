"""
Base parser for SCA manifest parsing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.services.sca.models import Dependency


class BaseDependencyParser(ABC):
    manifest_type: str = ""
    ecosystem: str = ""

    @abstractmethod
    def parse(self, content: str) -> list[Dependency]:
        """Parse manifest content into normalized dependencies."""
        raise NotImplementedError

    def _validate_size(self, content: str, limit: int = 5 * 1024 * 1024):
        if len(content.encode("utf-8")) > limit:
            raise ValueError(f"Manifest exceeds size limit ({limit} bytes)")

    def _sanitize_name(self, name: str) -> str:
        # Prevent path traversal, huge names, malicious
        name = name.strip()
        if len(name) > 214:
            raise ValueError(f"Package name too long: {name[:50]}")
        if ".." in name or "/" in name or "\\" in name:
            # Allow scoped npm like @babel/core, but not traversal
            if not name.startswith("@"):
                raise ValueError(f"Invalid package name: {name}")
        return name
