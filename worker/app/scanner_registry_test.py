from app.scanner.manager import ScannerManager


def main():

    manager = ScannerManager()

    print("Available scanners:")
    print("-" * 60)

    for scanner in manager.available_scanners():
        print(f"Name: {scanner['name']}")
        print(f"Category: {scanner['category']}")
        print(f"Description: {scanner['description']}")
        print(f"Target types: {scanner['target_types']}")
        print("-" * 60)


if __name__ == "__main__":
    main()