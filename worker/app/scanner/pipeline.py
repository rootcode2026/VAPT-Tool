from app.finding_engine.engine import FindingEngine
from app.scanner.execution import (
    ScannerStageError,
    failed_scanner_result,
    get_max_attempts,
    run_with_retries,
)
from app.scanner.manager import ScannerManager
from app.scanner.parsers.registry import ParserRegistry


class ScannerPipeline:

    def __init__(self):
        self.manager = ScannerManager()
        self.parser_registry = ParserRegistry()
        self.finding_engine = FindingEngine()

    def run(self, scanner: str, target: str) -> dict:
        try:
            raw_output = self.manager.run(
                scanner=scanner,
                target=target,
            )
        except Exception as exc:
            raise ScannerStageError("execution", exc) from exc

        try:
            parser = self.parser_registry.get(scanner)
            parsed_result = parser.parse(raw_output)
        except Exception as exc:
            raise ScannerStageError("parsing", exc) from exc

        try:
            findings = self.finding_engine.analyze(
                parsed_result
            )
        except Exception as exc:
            raise ScannerStageError("analysis", exc) from exc

        return {
            "scanner": scanner,
            "status": "completed",
            "raw_output": raw_output,
            "parsed_result": parsed_result,
            "findings": findings,
        }

    def run_many(
        self,
        scanners: list[str],
        target: str,
        *,
        max_attempts: int | None = None,
        on_attempt_start=None,
        on_attempt_failure=None,
    ) -> list[dict]:
        """
        Run each scanner independently.

        A failure in one scanner does not prevent later scanners
        from executing. Scanner-specific behavior belongs in the
        individual scanner modules, not here.
        """

        attempts = max_attempts or get_max_attempts()
        results = []

        for scanner in scanners:
            try:
                results.append(
                    run_with_retries(
                        self.run,
                        scanner,
                        target,
                        max_attempts=attempts,
                        on_attempt_start=(
                            None
                            if on_attempt_start is None
                            else lambda attempt, name=scanner: on_attempt_start(
                                name,
                                attempt,
                            )
                        ),
                        on_attempt_failure=(
                            None
                            if on_attempt_failure is None
                            else lambda attempt, failure, name=scanner: on_attempt_failure(
                                name,
                                attempt,
                                failure,
                            )
                        ),
                    )
                )
            except Exception as exc:
                results.append(
                    failed_scanner_result(
                        scanner=scanner,
                        target=target,
                        error=exc,
                        max_attempts=attempts,
                    )
                )

        return results
