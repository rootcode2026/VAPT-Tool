from app.scanner.manager import ScannerManager
from app.scanner.parsers.registry import ParserRegistry
from app.finding_engine.engine import FindingEngine


class ScannerPipeline:

    def __init__(self):
        self.manager = ScannerManager()
        self.parser_registry = ParserRegistry()
        self.finding_engine = FindingEngine()

    def run(self, scanner: str, target: str) -> dict:
        # Step 1: Run scanner
        raw_output = self.manager.run(
            scanner=scanner,
            target=target,
        )

        # Step 2: Get parser dynamically
        parser = self.parser_registry.get(scanner)

        # Step 3: Parse raw scanner output
        # Every parser returns the same normalized structure.
        parsed_result = parser.parse(raw_output)

        # Step 4: Convert normalized findings into
        # standardized findings.
        findings = self.finding_engine.analyze(
            parsed_result
        )

        return {
            "scanner": scanner,
            "raw_output": raw_output,
            "parsed_result": parsed_result,
            "findings": findings,
        }