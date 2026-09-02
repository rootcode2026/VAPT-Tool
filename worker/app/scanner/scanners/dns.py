import ipaddress
from urllib.parse import urlparse

from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class DNSScanner(BaseScanner):
    name = "dns"
    category = "asset_discovery"
    description = "DNS record discovery for authorized domains"
    target_types = {"domain"}
    input_type = "target"
    output_format = "jsonl"

    capabilities = {
        "dns_record_discovery",
        "a_record_lookup",
        "aaaa_record_lookup",
        "cname_lookup",
        "mx_lookup",
        "ns_lookup",
        "txt_lookup",
        "soa_lookup",
    }

    requirements = [
        "network_access",
        "docker",
    ]

    timeout = 120

    IMAGE = "vapt-dns:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        domain = self._normalize_target(target)

        command = [
            domain,
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-ns",
            "-txt",
            "-soa",
            "-json",
            "-silent",
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=self.timeout,
        )

    def _normalize_target(self, target: str) -> str:
        target = target.strip().rstrip(".")

        if not target:
            raise ValueError("DNS target cannot be empty.")

        if "://" in target:
            host = urlparse(target).hostname
            if not host:
                raise ValueError("DNS target host is missing.")
            target = host

        try:
            ipaddress.ip_address(target)
        except ValueError:
            return target.lower()

        raise ValueError(
            "DNS scanner only supports domain targets."
        )
