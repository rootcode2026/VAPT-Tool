import xml.etree.ElementTree as ET


class NmapParser:

    def parse(self, xml_output: str) -> dict:
        root = ET.fromstring(xml_output)

        result = {
            "scanner": "nmap",
            "version": root.attrib.get("version"),
            "hosts": [],
        }

        for host in root.findall("host"):
            host_data = {
                "status": None,
                "addresses": [],
                "hostnames": [],
                "ports": [],
            }

            # Host status
            status = host.find("status")

            if status is not None:
                host_data["status"] = status.attrib.get("state")

            # IP addresses
            for address in host.findall("address"):
                host_data["addresses"].append(
                    {
                        "address": address.attrib.get("addr"),
                        "type": address.attrib.get("addrtype"),
                    }
                )

            # Hostnames
            hostnames = host.find("hostnames")

            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    host_data["hostnames"].append(
                        hostname.attrib.get("name")
                    )

            # Ports
            ports = host.find("ports")

            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "port": int(port.attrib["portid"]),
                        "protocol": port.attrib.get("protocol"),
                        "state": None,
                        "service": None,
                        "product": None,
                        "version": None,
                    }

                    # Port state
                    state = port.find("state")

                    if state is not None:
                        port_data["state"] = state.attrib.get("state")

                    # Service information
                    service = port.find("service")

                    if service is not None:
                        port_data["service"] = service.attrib.get(
                            "name"
                        )
                        port_data["product"] = service.attrib.get(
                            "product"
                        )
                        port_data["version"] = service.attrib.get(
                            "version"
                        )

                    host_data["ports"].append(port_data)

            result["hosts"].append(host_data)

        return result