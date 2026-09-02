from app.scanner.base import BaseScanner
from app.scanner.docker_runner import DockerRunner


class NmapScanner(BaseScanner):

    # ---------------------------------------------------------
    # Identity
    # ---------------------------------------------------------

    name = "nmap"
    category = "recon"
    description = "Network and service discovery"

    # ---------------------------------------------------------
    # Target / Input
    # ---------------------------------------------------------

    target_types = {
        "domain",
        "ip",
    }

    input_type = "target"

    # ---------------------------------------------------------
    # Output
    # ---------------------------------------------------------

    output_format = "xml"

    # ---------------------------------------------------------
    # Capabilities
    # ---------------------------------------------------------

    capabilities = {
        "host_discovery",
        "port_scanning",
        "service_detection",
        "version_detection",
    }

    # ---------------------------------------------------------
    # Requirements
    # ---------------------------------------------------------

    requirements = [
        "network_access",
        "docker",
    ]

    # ---------------------------------------------------------
    # Execution
    # ---------------------------------------------------------

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