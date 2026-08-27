from app.scanner.registry import ScannerRegistry

registry = ScannerRegistry()

print("Available scanners:\n")

for scanner in registry.list():
    print(scanner)