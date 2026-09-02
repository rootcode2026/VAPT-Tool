from abc import ABC, abstractmethod
from typing import Any


class BaseScanner(ABC):

    # ---------------------------------------------------------
    # Identity
    # ---------------------------------------------------------

    name: str = ""
    category: str = ""
    description: str = ""

    # ---------------------------------------------------------
    # Target / Input
    # ---------------------------------------------------------

    target_types: set[str] = set()
    input_type: str = "target"

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
            target: Target to scan.

        Returns:
            Raw scanner output.
        """
        raise NotImplementedError

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
            "target_types": sorted(
                self.target_types
            ),
            "input_type": self.input_type,
            "output_format": self.output_format,
            "capabilities": sorted(
                self.capabilities
            ),
            "requirements": list(
                self.requirements
            ),
            "timeout": self.timeout,
        }