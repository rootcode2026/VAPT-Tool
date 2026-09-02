from app.scanner.pipeline import ScannerPipeline


def main():

    pipeline = ScannerPipeline()

    print("Testing HTTP fingerprint pipeline...")
    print()

    result = pipeline.run(
        scanner="http_fingerprint",
        target="https://example.com",
    )

    print("Scanner:", result["scanner"])
    print("Assets:", len(result["parsed_result"]["assets"]))
    print("Findings:", len(result["findings"]))
    print()

    print("Findings:")
    print("-" * 70)

    for finding in result["findings"]:
        print(
            f"- {finding['title']} "
            f"| severity={finding['severity']} "
            f"| score={finding['score']}"
        )


if __name__ == "__main__":
    main()