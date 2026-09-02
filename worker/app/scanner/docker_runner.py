import time

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound


class ScannerExecutionError(RuntimeError):
    """Base error for scanner container execution."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
        duration: float | None = None,
    ):
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.duration = duration


class ScannerFailureError(ScannerExecutionError):
    """Scanner container exited with a non-zero status."""


class ScannerTimeoutError(ScannerExecutionError):
    """Scanner container exceeded the configured timeout."""


class DockerRunnerError(ScannerExecutionError):
    """Docker image, API, or container startup failure."""


class DockerRunResult:
    def __init__(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        duration: float,
        timed_out: bool,
    ):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration
        self.timed_out = timed_out

    @property
    def output(self) -> str:
        if self.stdout:
            return self.stdout

        return self.stderr


class DockerRunner:
    DIAGNOSTIC_LIMIT = 4000

    def __init__(self, client=None):
        self.client = client or docker.from_env()

    def run(
        self,
        image: str,
        command: list[str],
        timeout: int = 300,
    ) -> str:
        """
        Run a scanner container and return stdout for parsers.

        Existing scanners depend on a string result. Richer execution
        details are available on exceptions and via run_detailed().
        """

        return self.run_detailed(
            image=image,
            command=command,
            timeout=timeout,
        ).output

    def run_detailed(
        self,
        image: str,
        command: list[str],
        timeout: int = 300,
    ) -> DockerRunResult:
        container = None
        started = time.monotonic()

        try:
            try:
                container = self.client.containers.run(
                    image=image,
                    command=command,
                    detach=True,
                    remove=False,
                )
            except ImageNotFound as exc:
                raise DockerRunnerError(
                    self._safe_message(
                        f"Scanner image was not found: {image}"
                    ),
                    duration=self._duration(started),
                ) from exc
            except (APIError, DockerException, OSError) as exc:
                raise DockerRunnerError(
                    self._safe_message(
                        f"Failed to start scanner container: {exc}"
                    ),
                    duration=self._duration(started),
                ) from exc

            try:
                wait_result = container.wait(timeout=timeout)
            except Exception as exc:
                duration = self._duration(started)

                if self._is_timeout(exc):
                    self._stop_container(container)
                    stdout, stderr = self._read_logs(container)

                    raise ScannerTimeoutError(
                        self._safe_message(
                            "Scanner timed out after "
                            f"{timeout} seconds."
                        ),
                        exit_code=None,
                        stdout=stdout,
                        stderr=stderr,
                        timed_out=True,
                        duration=duration,
                    ) from exc

                self._stop_container(container)
                stdout, stderr = self._read_logs(container)

                raise DockerRunnerError(
                    self._safe_message(
                        f"Failed while waiting for scanner: {exc}"
                    ),
                    stdout=stdout,
                    stderr=stderr,
                    duration=duration,
                ) from exc

            duration = self._duration(started)
            stdout, stderr = self._read_logs(container)
            exit_code = 1

            if isinstance(wait_result, dict):
                exit_code = int(wait_result.get("StatusCode", 1))
            elif isinstance(wait_result, int):
                exit_code = wait_result

            result = DockerRunResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
                timed_out=False,
            )

            if exit_code != 0:
                raise ScannerFailureError(
                    self._format_failure(
                        exit_code=exit_code,
                        stdout=stdout,
                        stderr=stderr,
                    ),
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=False,
                    duration=duration,
                )

            return result

        finally:
            self._cleanup_container(container)

    def _read_logs(self, container) -> tuple[str, str]:
        if container is None:
            return "", ""

        try:
            stdout = container.logs(
                stdout=True,
                stderr=False,
            )
            stderr = container.logs(
                stdout=False,
                stderr=True,
            )
        except Exception:
            return "", ""

        return (
            self._decode(stdout),
            self._decode(stderr),
        )

    def _decode(self, value) -> str:
        if value is None:
            return ""

        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")

        return str(value)

    def _stop_container(self, container) -> None:
        if container is None:
            return

        try:
            container.kill()
        except Exception:
            try:
                container.stop(timeout=1)
            except Exception:
                pass

    def _cleanup_container(self, container) -> None:
        if container is None:
            return

        try:
            container.remove(force=True)
        except NotFound:
            pass
        except Exception:
            pass

    def _is_timeout(self, exc: Exception) -> bool:
        name = type(exc).__name__.lower()

        if "timeout" in name:
            return True

        message = str(exc).lower()

        return "timeout" in message or "timed out" in message

    def _duration(self, started: float) -> float:
        return round(time.monotonic() - started, 3)

    def _format_failure(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> str:
        diagnostic = stderr.strip() or stdout.strip()
        diagnostic = self._truncate(diagnostic)

        if diagnostic:
            return (
                f"Scanner failed with exit code {exit_code}: "
                f"{diagnostic}"
            )

        return f"Scanner failed with exit code {exit_code}."

    def _truncate(self, value: str) -> str:
        if len(value) <= self.DIAGNOSTIC_LIMIT:
            return value

        return value[: self.DIAGNOSTIC_LIMIT] + "..."

    def _safe_message(self, message: str) -> str:
        redacted = message

        for token in (
            "password",
            "secret",
            "token",
            "api_key",
            "authorization",
        ):
            if token in redacted.lower():
                redacted = (
                    "Scanner execution failed. "
                    "See scanner logs for details."
                )
                break

        return self._truncate(redacted)
