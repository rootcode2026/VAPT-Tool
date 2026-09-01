from app.scanner.parsers.base import BaseParser
from app.scanner.parsers.nmap_parser import NmapParser
from app.scanner.parsers.nuclei_parser import NucleiParser


class ParserRegistry:

    def __init__(self):
        self._parsers: dict[str, BaseParser] = {}
        self._register_builtin_parsers()

    def _register_builtin_parsers(self):
        self.register(NmapParser())
        self.register(NucleiParser())

    def register(self, parser: BaseParser):
        if not parser.scanner_name:
            raise ValueError(
                "Parser must define a scanner_name."
            )

        if parser.scanner_name in self._parsers:
            raise ValueError(
                f"Parser for scanner "
                f"'{parser.scanner_name}' is already registered."
            )

        self._parsers[parser.scanner_name] = parser

    def get(self, scanner_name: str) -> BaseParser:
        parser = self._parsers.get(scanner_name)

        if parser is None:
            raise ValueError(
                f"No parser registered for scanner "
                f"'{scanner_name}'."
            )

        return parser

    def list(self) -> list[str]:
        return sorted(self._parsers.keys())