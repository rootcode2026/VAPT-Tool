from app.scanner.parsers.registry import ParserRegistry


def main():

    registry = ParserRegistry()

    print("Available parsers:")
    print("-" * 60)

    for scanner_name in registry.list():
        parser = registry.get(scanner_name)

        print(f"Scanner: {scanner_name}")
        print(f"Parser: {parser.__class__.__name__}")
        print("-" * 60)


if __name__ == "__main__":
    main()
