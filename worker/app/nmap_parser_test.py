from app.scanner.scanners.nmap import NmapScanner
from app.scanner.parsers.nmap_parser import NmapParser


def main():
    scanner = NmapScanner()

    print("Running Nmap scan...")

    xml_output = scanner.scan("192.168.1.100")

    parser = NmapParser()

    result = parser.parse(xml_output)

    print("\nParsed result:")
    print(result)


if __name__ == "__main__":
    main()