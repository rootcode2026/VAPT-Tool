from app.finding_engine.engine import FindingEngine


def main():
    scan_result = {
        "scanner": "nmap",
        "version": "7.93",
        "hosts": [
            {
                "status": "up",
                "addresses": [
                    {
                        "address": "192.168.1.100",
                        "type": "ipv4",
                    }
                ],
                "hostnames": [],
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": None,
                        "version": None,
                    },
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "https",
                        "product": None,
                        "version": None,
                    },
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http-proxy",
                        "product": None,
                        "version": None,
                    },
                ],
            }
        ],
    }

    engine = FindingEngine()

    findings = engine.analyze(scan_result)

    print("Findings:")

    for finding in findings:
        print(finding)


if __name__ == "__main__":
    main()