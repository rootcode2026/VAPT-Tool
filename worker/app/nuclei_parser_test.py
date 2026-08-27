from app.scanner.scanners.nuclei import NucleiScanner
from app.scanner.parsers.nuclei_parser import NucleiParser


def main():
    scanner = NucleiScanner()

    raw_output = scanner.scan(
        "http://host.docker.internal:8000"
    )

    parser = NucleiParser()

    findings = parser.parse(raw_output)

    print(f"\nFindings parsed: {len(findings)}\n")

    for finding in findings:
        print(finding)


if __name__ == "__main__":
    main()