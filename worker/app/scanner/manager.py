from app.scanner.registry import ScannerRegistry


class ScannerManager:

    def __init__(self):
        self.registry = ScannerRegistry()

    def run(
        self,
        scanner: str,
        target: str,
        target_type: str | None = None,
    ) -> str:

        scanner_instance = self.registry.get(scanner)

        if target_type is not None:
            if target_type not in scanner_instance.target_types:
                raise ValueError(
                    f"Scanner '{scanner}' does not support "
                    f"target type '{target_type}'. "
                    f"Supported types: "
                    f"{sorted(scanner_instance.target_types)}"
                )

        return scanner_instance.scan(target)

    def available_scanners(self):
        return self.registry.list()