from app.scanner.manager import ScannerManager


def main():

    manager = ScannerManager()

    print("Testing HTTP fingerprint scanner...")
    print()

    raw_output = manager.run(
        scanner="http_fingerprint",
        target="https://example.com",
    )

    print(raw_output)


if __name__ == "__main__":
    main()