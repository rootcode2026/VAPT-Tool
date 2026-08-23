from app.risk_engine.engine import RiskAssessmentEngine


def run_test(name, findings):
    engine = RiskAssessmentEngine()

    result = engine.calculate(findings)

    print(f"\n{name}")
    print("-" * 40)
    print(result)


def main():

    # No findings
    run_test(
        "Test 1 - No findings",
        [],
    )

    # One low
    run_test(
        "Test 2 - One low",
        [
            {"severity": "low"},
        ],
    )

    # Medium + low
    run_test(
        "Test 3 - Medium + low",
        [
            {"severity": "medium"},
            {"severity": "low"},
        ],
    )

    # High + medium
    run_test(
        "Test 4 - High + medium",
        [
            {"severity": "high"},
            {"severity": "medium"},
        ],
    )

    # Critical
    run_test(
        "Test 5 - Critical",
        [
            {"severity": "critical"},
        ],
    )

    # Multiple high findings
    run_test(
        "Test 6 - Multiple high findings",
        [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "high"},
        ],
    )


if __name__ == "__main__":
    main()