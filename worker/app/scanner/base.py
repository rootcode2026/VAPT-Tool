from abc import ABC, abstractmethod


class BaseScanner(ABC):

    name: str = ""
    category: str = ""
    description: str = ""
    target_types: set[str] = set()

    @abstractmethod
    def scan(self, target: str) -> str:
        """
        Execute a security scan against the target.

        Returns:
            Raw scanner output as a string.
        """
        raise NotImplementedError