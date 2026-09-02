from urllib.parse import urlparse

from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class TLSScanner(BaseScanner):
    name = "tls"
    category = "tls"
    description = (
        "TLS/SSL protocol, cipher, and certificate security analysis"
    )
    target_types = {"url", "domain", "ip"}
    input_type = "target"
    output_format = "json"

    capabilities = {
        "tls_protocol_analysis",
        "cipher_suite_analysis",
        "certificate_analysis",
        "tls_vulnerability_detection",
    }

    requirements = [
        "network_access",
        "docker",
    ]

    timeout = 900

    IMAGE = "vapt-tls:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        target = target.strip()

        if not target:
            raise ValueError("TLS target cannot be empty.")

        normalized_target = self._normalize_target(target)

        command = [normalized_target]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=self.timeout,
        )

    def _normalize_target(self, target: str) -> str:
        if "://" not in target:
            return target

        parsed = urlparse(target)
        host = parsed.hostname

        if not host:
            raise ValueError("TLS target host is missing.")

        if parsed.port:
            return f"{host}:{parsed.port}"

        return host
