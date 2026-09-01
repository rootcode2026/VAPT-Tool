import json

from app.scanner.parsers.base import BaseParser


class NucleiParser(BaseParser):

    scanner_name = "nuclei"

    def parse(self, raw_output: str) -> dict:
        findings = []

        for line in raw_output.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            classification = info.get("classification", {})

            severity = info.get(
                "severity",
                "info",
            ).lower()

            findings.append(
                {
                    "scanner": "nuclei",
                    "title": info.get(
                        "name",
                        data.get(
                            "template-id",
                            "Nuclei finding",
                        ),
                    ),
                    "description": info.get(
                        "description",
                        "",
                    ),
                    "severity": severity,
                    "score": self._severity_score(
                        severity
                    ),
                    "status": "open",
                    "evidence": self._build_evidence(
                        data
                    ),
                    "remediation": (
                        "Review the detected issue and apply "
                        "the recommended security configuration "
                        "or remediation."
                    ),
                    "cve": self._get_cve(
                        classification
                    ),
                    "cwe": self._get_cwe(
                        classification
                    ),
                }
            )

        return {
            "scanner": "nuclei",
            "assets": [],
            "findings": findings,
        }

    def _severity_score(self, severity: str) -> int:
        scores = {
            "critical": 90,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 5,
        }

        return scores.get(severity, 5)

    def _get_cve(self, classification: dict):
        cve_id = classification.get("cve-id")

        if isinstance(cve_id, list):
            return cve_id[0] if cve_id else None

        return cve_id

    def _get_cwe(self, classification: dict):
        cwe_id = classification.get("cwe-id")

        if isinstance(cwe_id, list):
            return cwe_id[0] if cwe_id else None

        return cwe_id

    def _build_evidence(self, data: dict) -> str:
        matched_at = data.get("matched-at")
        matcher_name = data.get("matcher-name")
        extracted_results = data.get("extracted-results")

        evidence = []

        if matched_at:
            evidence.append(
                f"Matched at: {matched_at}"
            )

        if matcher_name:
            evidence.append(
                f"Matcher: {matcher_name}"
            )

        if extracted_results:
            evidence.append(
                f"Extracted: "
                f"{', '.join(map(str, extracted_results))}"
            )

        return " | ".join(evidence)