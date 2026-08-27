from app.scanner.base import BaseScanner
from app.scanner.scanners.nmap import NmapScanner
from app.scanner.scanners.nuclei import NucleiScanner


class ScannerRegistry:
    def __init__(self):
        self._scanners: dict[str, BaseScanner] = {}
        self.register(NmapScanner())
        self.register(NucleiScanner())

    def register(self, scanner: BaseScanner):
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> BaseScanner:
        if name not in self._scanners:
            raise ValueError(f"Scanner '{name}' is not registered.")
        return self._scanners[name]

    def list(self):
        return [
            {
                "name": scanner.name,
                "category": scanner.category,
                "description": scanner.description,
                "target_types": sorted(scanner.target_types),
            }
            for scanner in self._scanners.values()
        ]