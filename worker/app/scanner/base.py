from abc import ABC, abstractmethod
from typing import Any


class BaseScanner(ABC):

    name: str = ""
    category: str = ""
    description: str = ""
    target_types: set[str] = set()

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

    def metadata(self) -> dict[str, Any]:
        """
        Return scanner metadata for the API,
        dashboard, and scanner management system.
        """

        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "target_types": sorted(self.target_types),
            "timeout": self.timeout,
        }