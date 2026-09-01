from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class NucleiScanner(BaseScanner):

    name = "nuclei"

    category = "vulnerability"

    description = (
        "Template-based vulnerability and "
        "security misconfiguration detection"
    )

    target_types = {
        "url",
        "domain",
        "ip",
    }

    timeout = 600

    IMAGE = "vapt-nuclei:latest"

    TEMPLATE_PATH = "/root/nuclei-templates"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:

        command = [
            "-u",
            target,
            "-t",
            self.TEMPLATE_PATH,
            "-jsonl",
            "-silent",
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=self.timeout,
        )