from app.scanner.scanners.nuclei import NucleiScanner


def main():
    scanner = NucleiScanner()

    result = scanner.scan(
        "http://host.docker.internal:8000"
    )

    print(result)


if __name__ == "__main__":
    main()