from app.scanner.base import BaseScanner
from app.scanner.scanners.nmap import NmapScanner
from app.scanner.scanners.nuclei import NucleiScanner


class ScannerRegistry:

    def __init__(self):
        self._scanners: dict[str, BaseScanner] = {}

        self._register_builtin_scanners()

    # ---------------------------------------------------------
    # Registration
    # ---------------------------------------------------------

    def _register_builtin_scanners(self):
        self.register(NmapScanner())
        self.register(NucleiScanner())

    def register(self, scanner: BaseScanner):
        if not scanner.name:
            raise ValueError(
                "Scanner must define a name."
            )

        if scanner.name in self._scanners:
            raise ValueError(
                f"Scanner '{scanner.name}' is already registered."
            )

        self._scanners[scanner.name] = scanner

    # ---------------------------------------------------------
    # Retrieval
    # ---------------------------------------------------------

    def get(self, name: str) -> BaseScanner:

        scanner = self._scanners.get(name)

        if scanner is None:
            raise ValueError(
                f"Scanner '{name}' is not registered."
            )

        return scanner

    # ---------------------------------------------------------
    # Listing
    # ---------------------------------------------------------

    def list(self) -> list[dict]:

        return [
            scanner.metadata()
            for scanner in self._scanners.values()
        ]