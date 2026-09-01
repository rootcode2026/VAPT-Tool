import xml.etree.ElementTree as ET

from app.scanner.parsers.base import BaseParser


class NmapParser(BaseParser):

    scanner_name = "nmap"

    def parse(self, xml_output: str) -> dict:
        root = ET.fromstring(xml_output)

        assets = []
        findings = []

        for host in root.findall("host"):

            asset = {
                "status": None,
                "addresses": [],
                "hostnames": [],
                "ports": [],
            }

            # Host status
            status = host.find("status")

            if status is not None:
                asset["status"] = status.attrib.get(
                    "state"
                )

            # IP addresses
            for address in host.findall("address"):
                asset["addresses"].append(
                    {
                        "address": address.attrib.get(
                            "addr"
                        ),
                        "type": address.attrib.get(
                            "addrtype"
                        ),
                    }
                )

            # Hostnames
            hostnames = host.find("hostnames")

            if hostnames is not None:
                for hostname in hostnames.findall(
                    "hostname"
                ):
                    asset["hostnames"].append(
                        hostname.attrib.get("name")
                    )

            # Ports
            ports = host.find("ports")

            if ports is not None:
                for port in ports.findall("port"):

                    port_data = {
                        "port": int(
                            port.attrib["portid"]
                        ),
                        "protocol": port.attrib.get(
                            "protocol"
                        ),
                        "state": None,
                        "service": None,
                        "product": None,
                        "version": None,
                    }

                    # Port state
                    state = port.find("state")

                    if state is not None:
                        port_data["state"] = (
                            state.attrib.get("state")
                        )

                    # Service information
                    service = port.find("service")

                    if service is not None:
                        port_data["service"] = (
                            service.attrib.get("name")
                        )

                        port_data["product"] = (
                            service.attrib.get("product")
                        )

                        port_data["version"] = (
                            service.attrib.get("version")
                        )

                    asset["ports"].append(port_data)

                    # Generate normalized findings
                    if port_data["state"] == "open":
                        finding = self._build_port_finding(
                            port_data,
                            asset,
                        )

                        if finding is not None:
                            findings.append(finding)

            assets.append(asset)

        return {
            "scanner": "nmap",
            "version": root.attrib.get("version"),
            "assets": assets,
            "findings": findings,
        }

    def _build_port_finding(
        self,
        port: dict,
        asset: dict,
    ) -> dict | None:

        port_number = port["port"]

        address = self._get_primary_address(
            asset
        )

        if port_number == 80:
            return {
                "scanner": "nmap",
                "title": "HTTP service exposed",
                "description": (
                    "An HTTP service is exposed "
                    "on port 80."
                ),
                "severity": "low",
                "score": 25,
                "status": "open",
                "evidence": (
                    f"Host {address} has "
                    f"port 80/tcp open."
                ),
                "remediation": (
                    "Use HTTPS instead of unencrypted "
                    "HTTP where possible."
                ),
                "cve": None,
                "cwe": "CWE-319",
            }

        if port_number == 8080:
            return {
                "scanner": "nmap",
                "title": (
                    "Service exposed on port 8080"
                ),
                "description": (
                    "A service is exposed on "
                    "port 8080."
                ),
                "severity": "medium",
                "score": 45,
                "status": "open",
                "evidence": (
                    f"Host {address} has "
                    f"port 8080/tcp open."
                ),
                "remediation": (
                    "Verify that the service is required "
                    "and restrict access where possible."
                ),
                "cve": None,
                "cwe": None,
            }

        return None

    def _get_primary_address(
        self,
        asset: dict,
    ) -> str:

        addresses = asset.get("addresses", [])

        if not addresses:
            return "unknown"

        return addresses[0].get(
            "address",
            "unknown",
        )