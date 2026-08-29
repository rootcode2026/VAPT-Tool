from app.scanner.manager import ScannerManager
from app.scanner.parsers.nmap_parser import NmapParser
from app.scanner.parsers.nuclei_parser import NucleiParser
from app.finding_engine.engine import FindingEngine


class ScannerPipeline:

    def __init__(self):
        self.manager = ScannerManager()
        self.finding_engine = FindingEngine()

    def run(
        self,
        scanner: str,
        target: str,
    ) -> dict:

        if scanner == "nmap":

            raw_output = self.manager.run(
                scanner="nmap",
                target=target,
            )

            parser = NmapParser()
            parsed_result = parser.parse(raw_output)

            findings = self.finding_engine.analyze(
                parsed_result
            )

            return {
                "scanner": "nmap",
                "raw_output": raw_output,
                "parsed_result": parsed_result,
                "findings": findings,
            }

        if scanner == "nuclei":

            raw_output = self.manager.run(
                scanner="nuclei",
                target=target,
            )

            parser = NucleiParser()

            parsed_findings = parser.parse(
                raw_output
            )

            parsed_result = {
                "scanner": "nuclei",
                "findings": parsed_findings,
            }

            findings = self.finding_engine.analyze(
                parsed_result
            )

            return {
                "scanner": "nuclei",
                "raw_output": raw_output,
                "parsed_result": parsed_result,
                "findings": findings,
            }

        raise ValueError(
            f"Unsupported scanner: {scanner}"
        )