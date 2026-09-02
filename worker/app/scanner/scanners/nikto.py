from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class NiktoScanner(BaseScanner):
    name = "nikto"
    category = "web_vulnerability"
    description = (
        "Web server misconfiguration and known-vulnerability scanning"
    )
    target_types = {"url", "domain"}
    input_type = "target"
    output_format = "json"

    capabilities = {
        "web_vulnerability_scanning",
        "misconfiguration_detection",
        "known_vulnerability_detection",
        "security_header_analysis",
    }

    requirements = [
        "network_access",
        "docker",
    ]

    timeout = 600

    IMAGE = "vapt-nikto:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        target = target.strip()

        if not target:
            raise ValueError("Nikto target cannot be empty.")

        normalized_target = self._normalize_target(target)

        command = [
            "-h",
            normalized_target,
            "-ask",
            "no",
            "-nointeractive",
            "-Format",
            "json",
            "-output",
            "/dev/stdout",
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
