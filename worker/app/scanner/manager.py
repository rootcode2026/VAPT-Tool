from app.scanner.registry import ScannerRegistry


class ScannerManager:
    def __init__(self):
        self.registry = ScannerRegistry()

    def run(self, scanner: str, target: str) -> str:
        scanner_instance = self.registry.get(scanner)
        return scanner_instance.scan(target)

    def available_scanners(self):
        return self.registry.list()