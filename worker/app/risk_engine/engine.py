class RiskAssessmentEngine:

    GRADE_THRESHOLDS = {
        "A": 90,
        "B": 75,
        "C": 50,
        "D": 0,
    }

    # Info findings don't reduce the score.
    SEVERITY_WEIGHTS = {
        "critical": 35,
        "high": 20,
        "medium": 10,
        "low": 3,
        "info": 0,
    }

    def calculate(self, findings: list[dict]) -> dict:

        if not findings:
            return self._result(100, {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            })

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        deductions = 0

        for finding in findings:
            severity = finding.get("severity", "info").lower()

            if severity not in counts:
                severity = "info"

            counts[severity] += 1
            deductions += self.SEVERITY_WEIGHTS[severity]

        score = max(0, 100 - deductions)

        return self._result(score, counts)

    def _result(self, score: int, counts: dict) -> dict:
        return {
            "score": score,
            "grade": self._grade(score),
            "risk_level": self._level(score),
            "total_findings": sum(counts.values()),
            **counts,
        }

    def _grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 50:
            return "C"
        return "D"

    def _level(self, score: int) -> str:
        if score >= 90:
            return "excellent"
        if score >= 75:
            return "good"
        if score >= 50:
            return "needs_attention"
        return "critical"