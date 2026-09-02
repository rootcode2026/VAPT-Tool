import ipaddress
from urllib.parse import urlparse

from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class SubdomainScanner(BaseScanner):
    name = "subdomain"
    category = "asset_discovery"
    description = (
        "Passive subdomain discovery for authorized domains"
    )
    target_types = {"domain"}
    input_type = "target"
    output_format = "jsonl"

    capabilities = {
        "subdomain_discovery",
        "passive_reconnaissance",
    }

    requirements = [
        "network_access",
        "docker",
    ]

    timeout = 180

    IMAGE = "vapt-subdomain:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        domain = self._normalize_target(target)

        command = [
            "-d",
            domain,
            "-silent",
            "-json",
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=self.timeout,
        )

    def _normalize_target(self, target: str) -> str:
        target = target.strip().rstrip(".")

        if not target:
            raise ValueError("Subdomain target cannot be empty.")

        if "://" in target:
            host = urlparse(target).hostname
            if not host:
                raise ValueError("Subdomain target host is missing.")
            target = host

        try:
            ipaddress.ip_address(target)
        except ValueError:
            return target.lower()

        raise ValueError(
            "Subdomain scanner only supports domain targets."
        )
