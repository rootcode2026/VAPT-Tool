from app.scanner.pipeline import ScannerPipeline


def main():

    pipeline = ScannerPipeline()

    print("Testing Nmap pipeline...")
    
    result = pipeline.run(
        scanner="nmap",
        target="example.com",
    )

    print()
    print("Scanner:", result["scanner"])
    print("Findings:", len(result["findings"]))

    for finding in result["findings"]:
        print(
            f"- {finding['title']} "
            f"| {finding['severity']}"
        )


if __name__ == "__main__":
    main()