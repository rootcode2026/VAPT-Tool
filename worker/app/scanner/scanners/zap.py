from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class ZAPScanner(BaseScanner):
    name = "zap"
    category = "web_vulnerability"
    description = "OWASP ZAP web application vulnerability scanning"
    target_types = {"url", "domain"}
    input_type = "target"
    output_format = "xml"

    capabilities = {
        "web_vulnerability_scanning",
        "active_scanning",
        "spidering",
        "security_header_analysis",
        "misconfiguration_detection",
    }

    requirements = [
        "network_access",
        "docker",
    ]

    timeout = 900

    IMAGE = "vapt-zap:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        target = target.strip()

        if not target:
            raise ValueError("ZAP target cannot be empty.")

        normalized_target = self._normalize_target(target)

        command = [
            "-cmd",
            "-quickurl",
            normalized_target,
            "-quickprogress",
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=self.timeout,
        )

    def _normalize_target(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target

        return f"https://{target}"