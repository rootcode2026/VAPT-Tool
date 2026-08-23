class FindingEngine:

    def analyze(self, scan_result: dict) -> list[dict]:
        findings = []

        for host in scan_result.get("hosts", []):
            for port in host.get("ports", []):

                if port.get("state") != "open":
                    continue

                port_number = port.get("port")
                service = port.get("service")

                # HTTP exposed
                if port_number == 80:
                    findings.append({
                        "scanner": "nmap",
                        "title": "HTTP service exposed",
                        "description": (
                            "An HTTP service is accessible over "
                            "unencrypted HTTP."
                        ),
                        "severity": "low",
                        "score": 25,
                        "status": "open",
                        "evidence": (
                            f"TCP port {port_number} is open "
                            f"and identified as {service}."
                        ),
                        "remediation": (
                            "Use HTTPS and redirect HTTP traffic "
                            "to the secure HTTPS endpoint."
                        ),
                        "cve": None,
                        "cwe": "CWE-319",
                    })

                # Common development/admin port
                if port_number == 8080:
                    findings.append({
                        "scanner": "nmap",
                        "title": "Service exposed on port 8080",
                        "description": (
                            "A service is exposed on TCP port 8080. "
                            "This port is commonly used by development, "
                            "proxy, and administrative applications."
                        ),
                        "severity": "medium",
                        "score": 45,
                        "status": "open",
                        "evidence": (
                            f"TCP port {port_number} is open "
                            f"and identified as {service}."
                        ),
                        "remediation": (
                            "Verify whether the service must be "
                            "internet-accessible. Restrict access "
                            "with firewall rules or authentication "
                            "if it is administrative or internal."
                        ),
                        "cve": None,
                        "cwe": None,
                    })

        return findings