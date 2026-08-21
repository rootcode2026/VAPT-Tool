from app.scanner.docker_runner import DockerRunner


class NmapScanner:
    IMAGE = "vapt-nmap:latest"

    def __init__(self):
        self.runner = DockerRunner()

    def scan(self, target: str) -> str:
        command = [
            "-sV",
            target,
        ]

        return self.runner.run(
            image=self.IMAGE,
            command=command,
            timeout=300,
        )