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

        # Step 3: Parse scanner output
        parsed_output = parser.parse(raw_output)

        # Step 4: Normalize parser output
        parsed_result = self._normalize_result(
            scanner=scanner,
            parsed_output=parsed_output,
        )

        # Step 5: Convert parsed result into findings
        findings = self.finding_engine.analyze(
            parsed_result
        )

        return {
            "scanner": scanner,
            "raw_output": raw_output,
            "parsed_result": parsed_result,
            "findings": findings,
        }

    def _normalize_result(
        self,
        scanner: str,
        parsed_output,
    ) -> dict:

        # Nmap parser already returns a normalized
        # scanner result.
        if scanner == "nmap":
            return parsed_output

        # Nuclei parser returns a list of findings.
        if scanner == "nuclei":
            return {
                "scanner": "nuclei",
                "findings": parsed_output,
            }

        raise ValueError(
            f"Unsupported scanner result format: {scanner}"
        )