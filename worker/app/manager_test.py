from app.scanner.manager import ScannerManager


def main():
    manager = ScannerManager()

    result = manager.run(
        scanner="nmap",
        target="192.168.1.100",
    )

    print(result)


if __name__ == "__main__":
    main()