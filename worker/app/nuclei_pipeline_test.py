from app.scanner.pipeline import ScannerPipeline


def main():

    pipeline = ScannerPipeline()

    print("Testing Nuclei pipeline...")
    print()

    result = pipeline.run(
        scanner="nuclei",
        target="https://example.com",
    )

    print("Scanner:", result["scanner"])
    print("Findings:", len(result["findings"]))

    for finding in result["findings"]:
        print(
            f"- {finding['title']} "
            f"| {finding['severity']} "
            f"| score={finding['score']}"
        )


if __name__ == "__main__":
    main()