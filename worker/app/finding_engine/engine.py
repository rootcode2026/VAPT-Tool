class FindingEngine:

    def analyze(self, scan_result: dict) -> list[dict]:
        """
        Analyze normalized scanner output and return
        standardized security findings.

        Expected normalized structure:

        {
            "scanner": "nmap",
            "assets": [...],
            "findings": [...]
        }

        Every parser is responsible for converting
        scanner-specific output into this structure.
        """

        scanner = scan_result.get("scanner")

        if not scanner:
            raise ValueError(
                "Scanner name is missing from scan result."
            )

        normalized_findings = scan_result.get(
            "findings",
            [],
        )

        findings = []

        for finding in normalized_findings:

            if not isinstance(finding, dict):
                continue

            findings.append(
                self._standardize_finding(
                    scanner=scanner,
                    finding=finding,
                )
            )

        return findings

    # ---------------------------------------------------------
    # STANDARDIZE FINDING
    # ---------------------------------------------------------

    def _standardize_finding(
        self,
        scanner: str,
        finding: dict,
    ) -> dict:

        severity = str(
            finding.get(
                "severity",
                "info",
            )
        ).lower()

        score = finding.get(
            "score",
            self._severity_score(severity),
        )

        return {
            "scanner": scanner,
            "title": finding.get(
                "title",
                f"{scanner} finding",
            ),
            "description": finding.get(
                "description",
                "",
            ),
            "severity": severity,
            "score": score,
            "status": finding.get(
                "status",
                "open",
            ),
            "evidence": finding.get(
                "evidence",
                "",
            ),
            "remediation": finding.get(
                "remediation",
                "",
            ),
            "cve": finding.get(
                "cve"
            ),
            "cwe": finding.get(
                "cwe"
            ),
        }

    # ---------------------------------------------------------
    # DEFAULT SEVERITY SCORE
    # ---------------------------------------------------------

    def _severity_score(
        self,
        severity: str,
    ) -> int:

        scores = {
            "critical": 90,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 5,
        }

        return scores.get(
            severity,
            5,
        )