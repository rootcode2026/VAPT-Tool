from app.scanner.base import ScanContext
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

    def run_with_context(
        self,
        scanner: str,
        context: ScanContext | str,
    ) -> str:
        """AppSec-ready execution — accepts ScanContext or legacy string."""
        if isinstance(context, str):
            return self.run(scanner, context)
        scanner_instance = self.registry.get(scanner)
        if context.target_type is not None:
            if context.target_type not in scanner_instance.target_types:
                raise ValueError(
                    f"Scanner '{scanner}' does not support "
                    f"target type '{context.target_type}'. "
                    f"Supported types: "
                    f"{sorted(scanner_instance.target_types)}"
                )
        # Prefer scan_with_context if overridden, else fallback to scan()
        # This preserves backward compatibility for all existing scanners
        return scanner_instance.scan_with_context(context)

    def available_scanners(self):
        return self.registry.list()