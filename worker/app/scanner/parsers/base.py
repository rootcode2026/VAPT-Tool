from abc import ABC, abstractmethod


class BaseParser(ABC):

    scanner_name: str = ""

    @abstractmethod
    def parse(self, raw_output: str) -> dict:
        """
        Parse raw scanner output into a normalized result.

        Every parser must return:

        {
            "scanner": "...",
            "assets": [...],
            "findings": [...]
        }
        """
        ...