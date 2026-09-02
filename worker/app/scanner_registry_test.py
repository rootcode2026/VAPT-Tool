from app.scanner.manager import ScannerManager


def main():

    manager = ScannerManager()

    print("Available scanners:")
    print("=" * 70)

    for scanner in manager.available_scanners():

        print(f"Name: {scanner['name']}")
        print(f"Category: {scanner['category']}")
        print(f"Description: {scanner['description']}")
        print(
            f"Target types: "
            f"{scanner['target_types']}"
        )
        print(
            f"Input type: "
            f"{scanner['input_type']}"
        )
        print(
            f"Output format: "
            f"{scanner['output_format']}"
        )
        print(
            f"Capabilities: "
            f"{scanner['capabilities']}"
        )
        print(
            f"Requirements: "
            f"{scanner['requirements']}"
        )
        print(
            f"Timeout: "
            f"{scanner['timeout']} seconds"
        )

        print("-" * 70)


if __name__ == "__main__":
    main()