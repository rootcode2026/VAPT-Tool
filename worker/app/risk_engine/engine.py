class RiskAssessmentEngine:

    GRADE_THRESHOLDS = {
        "A": 90,
        "B": 75,
        "C": 50,
        "D": 0,
    }

    SEVERITY_WEIGHTS = {
        "critical": 60,
        "high": 30,
        "medium": 15,
        "low": 5,
    }

    def calculate(self, findings: list[dict]) -> dict:

        if not findings:
            return {
                "score": 100,
                "grade": "A",
                "risk_level": "excellent",
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        risk_points = 0

        for finding in findings:
            severity = finding.get(
                "severity",
                "low",
            ).lower()

            if severity not in counts:
                severity = "low"

            counts[severity] += 1

            risk_points += self.SEVERITY_WEIGHTS[
                severity
            ]

        score = max(
            0,
            100 - risk_points,
        )

        grade = self._calculate_grade(score)

        risk_level = self._calculate_risk_level(
            score
        )

        return {
            "score": score,
            "grade": grade,
            "risk_level": risk_level,
            "total_findings": len(findings),
            **counts,
        }

    def _calculate_grade(
        self,
        score: int,
    ) -> str:

        if score >= 90:
            return "A"

        if score >= 75:
            return "B"

        if score >= 50:
            return "C"

        return "D"

    def _calculate_risk_level(
        self,
        score: int,
    ) -> str:

        if score >= 90:
            return "excellent"

        if score >= 75:
            return "good"

        if score >= 50:
            return "needs_attention"

        return "critical"