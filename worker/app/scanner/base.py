from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    """Normalized execution context for future AppSec scanners.

    Wraps the legacy `target: str` with optional workspace/project metadata.
    Existing scanners continue to use `scan(target)`. Future scanners (SAST,
    SCA, secrets, container, IaC, API) can override `scan_with_context`
    and consume workspace, target_type, project_id without breaking the
    pipeline.
    """

    target: str
    target_type: str | None = None
    project_id: str | None = None
    scan_id: str | None = None
    workspace: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseScanner(ABC):

    # ---------------------------------------------------------
    # Identity
    # ---------------------------------------------------------

    name: str = ""
    category: str = ""
    description: str = ""
    # Scanner family for AppSec grouping (network, web, dast, sast, sca,
    # secrets, container, iac, api, cloud). Optional, category remains
    # primary.
    family: str = ""

    # ---------------------------------------------------------
    # Target / Input
    # ---------------------------------------------------------

    target_types: set[str] = set()
    input_type: str = "target"
    # Whether scanner requires a filesystem workspace (source-code families)
    requires_workspace: bool = False
    # Profiles this scanner participates in (registry-driven, declarative)
    supported_profiles: set[str] = set()

    # ---------------------------------------------------------
    # Output
    # ---------------------------------------------------------

    output_format: str = "text"

    # ---------------------------------------------------------
    # Capabilities
    # ---------------------------------------------------------

    capabilities: set[str] = set()

    # ---------------------------------------------------------
    # Requirements
    # ---------------------------------------------------------

    requirements: list[str] = []

    # ---------------------------------------------------------
    # Execution
    # ---------------------------------------------------------

    timeout: int = 300

    @abstractmethod
    def scan(self, target: str) -> str:
        """
        Execute the security scan.

        Args:
            target: Target to scan (legacy string input).

        Returns:
            Raw scanner output.

        Future scanners should override `scan_with_context` for richer
        inputs (workspace, target_type, project_id). Default
        implementation delegates to `scan` for backward compatibility.
        """
        raise NotImplementedError

    def scan_with_context(self, context: ScanContext) -> str:
        """AppSec-ready entry point. Default delegates to legacy scan()."""
        return self.scan(context.target)

    # ---------------------------------------------------------
    # Metadata
    # ---------------------------------------------------------

    def metadata(self) -> dict[str, Any]:
        """
        Return scanner metadata for the API,
        dashboard, scanner management system,
        and scanner selection logic.
        """

        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "family": self.family or self.category,
            "target_types": sorted(
                self.target_types
            ),
            "input_type": self.input_type,
            "requires_workspace": bool(self.requires_workspace),
            "supported_profiles": sorted(self.supported_profiles),
            "output_format": self.output_format,
            "capabilities": sorted(
                self.capabilities
            ),
            "requirements": list(
                self.requirements
            ),
            "timeout": self.timeout,
        }