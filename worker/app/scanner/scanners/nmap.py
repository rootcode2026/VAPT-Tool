from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class NmapScanner(BaseScanner):

    name = "nmap"
    category = "recon"
    description = "Network and service discovery"

    target_types = {
        "domain",
        "ip",
    }

    timeout = 300

    IMAGE = "vapt-nmap:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:

        command = [
            "-sV",
            "-oX",
            "-",
            target,
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=self.timeout,
        )