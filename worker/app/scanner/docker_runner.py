import docker


class DockerRunner:
    def __init__(self):
        self.client = docker.from_env()

    def run(
        self,
        image: str,
        command: list[str],
        timeout: int = 300,
    ) -> str:

        container = None

        try:
            container = self.client.containers.run(
                image=image,
                command=command,
                detach=True,
                remove=False,
            )

            result = container.wait(timeout=timeout)

            logs = container.logs(
                stdout=True,
                stderr=True,
            ).decode(
                "utf-8",
                errors="replace",
            )

            status_code = result.get("StatusCode", 1)

            if status_code != 0:
                raise RuntimeError(
                    f"Scanner failed with exit code "
                    f"{status_code}:\n{logs}"
                )

            return logs

        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass