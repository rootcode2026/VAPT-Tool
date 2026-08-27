from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class NucleiScanner(BaseScanner):

    name = "nuclei"
    category = "vulnerability"
    description = "Template-based vulnerability and security misconfiguration detection"
    target_types = {"url", "domain", "ip"}

    IMAGE = "vapt-nuclei:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        command = [
            "-u",
            target,
            "-jsonl",
            "-silent",
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=600,
        )