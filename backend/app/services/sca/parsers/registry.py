from app.services.sca.parsers.base import BaseDependencyParser
from app.services.sca.parsers.package_json import PackageJsonParser
from app.services.sca.parsers.package_lock import PackageLockParser
from app.services.sca.parsers.requirements import RequirementsParser
from app.services.sca.parsers.pyproject import PyprojectParser
from app.services.sca.parsers.poetry_lock import PoetryLockParser


class SCARegistry:
    def __init__(self):
        self._parsers: dict[str, BaseDependencyParser] = {}
        self._register_builtin()

    def _register_builtin(self):
        self.register(PackageJsonParser())
        self.register(PackageLockParser())
        self.register(RequirementsParser())
        self.register(PyprojectParser())
        self.register(PoetryLockParser())

    def register(self, parser: BaseDependencyParser):
        if not parser.manifest_type:
            raise ValueError("Parser must define manifest_type")
        if parser.manifest_type in self._parsers:
            raise ValueError(f"Parser for {parser.manifest_type} already registered")
        self._parsers[parser.manifest_type] = parser

    def get(self, manifest_type: str) -> BaseDependencyParser:
        parser = self._parsers.get(manifest_type)
        if parser is None:
            raise ValueError(f"No parser for manifest type '{manifest_type}'")
        return parser

    def list(self) -> list[str]:
        return sorted(self._parsers.keys())

    def parse(self, manifest_type: str, content: str):
        return self.get(manifest_type).parse(content)
