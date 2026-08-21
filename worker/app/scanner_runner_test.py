from app.scanner.scanners.nmap import NmapScanner


def main():
    scanner = NmapScanner()

    result = scanner.scan(
        "192.168.1.100"
    )

    print(result)


if __name__ == "__main__":
    main()