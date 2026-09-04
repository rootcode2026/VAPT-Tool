import time

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from requests.exceptions import ChunkedEncodingError, ReadTimeout
from urllib3.exceptions import ProtocolError
from urllib3.exceptions import ReadTimeoutError as Urllib3ReadTimeoutError


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
        scanner: str | None = None,
        target: str | None = None,
        phase: str | None = None,
        error_type: str | None = None,
        original_error: str | None = None,
    ):
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.duration = duration
        self.scanner = scanner
        self.target = target
        self.phase = phase
        self.error_type = error_type
        self.original_error = original_error


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
    POLL_INTERVAL = 1.0
    TERMINAL_STATES = {"exited", "dead", "removing"}

    def __init__(self, client=None):
        self.client = client or docker.from_env()

    def _validate_volumes(self, volumes: dict | None) -> dict:
        """AppSec hardening: validate workspace mounts, prevent host escape."""
        if not volumes:
            return {}
        if not isinstance(volumes, dict):
            raise ValueError("Volumes must be a dict")
        # Only allow absolute host paths, no traversal, not sensitive roots
        forbidden = {"/", "/etc", "/var/run", "/var/run/docker.sock", "/root"}
        cleaned: dict = {}
        for host, container_cfg in volumes.items():
            host_str = str(host).strip()
            # Handle both Unix (/tmp) and Windows (C:\Users\...) absolute paths
            is_windows_abs = len(host_str) >= 2 and host_str[1] == ":" and host_str[0].isalpha()
            is_unix_abs = host_str.startswith("/")
            if not (is_windows_abs or is_unix_abs):
                raise ValueError(f"Volume host path must be absolute: {host_str}")
            # Check traversal for both separators
            parts = host_str.replace("\\", "/").split("/")
            if ".." in parts:
                raise ValueError(f"Volume host path must not contain traversal: {host_str}")
            if host_str in forbidden or host_str.startswith("/etc/") or host_str.startswith("/var/run/"):
                # Allow /tmp and /workspace only for scanner workspaces
                if not (host_str.startswith("/tmp/") or host_str.startswith("/workspace")):
                    raise ValueError(f"Volume host path not allowed: {host_str}")
            cleaned[host_str] = container_cfg
        return cleaned

    def run(
        self,
        image: str,
        command: list[str],
        timeout: int = 300,
        scanner: str | None = None,
        target: str | None = None,
        volumes: dict | None = None,
        workspace: str | None = None,
    ) -> str:
        """
        Run a scanner container and return stdout for parsers.

        Existing scanners depend on a string result. Richer execution
        details are available on exceptions and via run_detailed().
        AppSec scanners may pass `volumes` for workspace mounts.
        """

        return self.run_detailed(
            image=image,
            command=command,
            timeout=timeout,
            scanner=scanner,
            target=target,
            volumes=volumes,
            workspace=workspace,
        ).output

    def run_detailed(
        self,
        image: str,
        command: list[str],
        timeout: int = 300,
        scanner: str | None = None,
        target: str | None = None,
        volumes: dict | None = None,
        workspace: str | None = None,
    ) -> DockerRunResult:
        container = None
        started = time.monotonic()
        scanner_name = scanner or image
        target_name = (
            target
            if target is not None
            else " ".join(str(part) for part in command)
        )
        phase = "starting"

        # AppSec hardening: validate volumes before container creation
        validated_volumes = self._validate_volumes(volumes)
        # Workspace convenience: if workspace provided, mount read-only
        if workspace and workspace not in validated_volumes:
            ws = str(workspace).strip()
            if ws and ws.startswith("/") and ".." not in ws.split("/"):
                # Mount workspace as /workspace read-only by default
                validated_volumes[ws] = {"bind": "/workspace", "mode": "ro"}

        try:
            try:
                run_kwargs: dict = dict(
                    image=image,
                    command=command,
                    detach=True,
                    remove=False,
                )
                if validated_volumes:
                    run_kwargs["volumes"] = validated_volumes
                container = self.client.containers.run(**run_kwargs)
            except ImageNotFound as exc:
                raise self._build_error(
                    DockerRunnerError,
                    f"Scanner image was not found: {image}",
                    cause=exc,
                    started=started,
                    phase="starting",
                    scanner=scanner_name,
                    target=target_name,
                ) from exc
            except (APIError, DockerException, OSError) as exc:
                raise self._build_error(
                    DockerRunnerError,
                    "Failed to start scanner container",
                    cause=exc,
                    started=started,
                    phase="starting",
                    scanner=scanner_name,
                    target=target_name,
                ) from exc

            phase = "running"
            try:
                phase = "waiting"
                wait_result = self._wait_for_exit(
                    container,
                    timeout=timeout,
                    started=started,
                )
            except ScannerTimeoutError:
                raise
            except Exception as exc:
                duration = self._duration(started)
                self._stop_container(container)
                phase = "log collection"
                stdout, stderr = self._read_logs(container)

                if self._is_timeout(exc) and not self._is_transport_error(exc):
                    raise self._build_error(
                        ScannerTimeoutError,
                        f"Scanner timed out after {timeout} seconds.",
                        cause=exc,
                        started=started,
                        phase="waiting",
                        scanner=scanner_name,
                        target=target_name,
                        exit_code=None,
                        stdout=stdout,
                        stderr=stderr,
                        timed_out=True,
                    ) from exc

                raise self._build_error(
                    DockerRunnerError,
                    "Failed while waiting for scanner",
                    cause=exc,
                    started=started,
                    phase="waiting",
                    scanner=scanner_name,
                    target=target_name,
                    stdout=stdout,
                    stderr=stderr,
                    duration=duration,
                ) from exc

            phase = "log collection"
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
                raise self._build_error(
                    ScannerFailureError,
                    self._format_failure(
                        exit_code=exit_code,
                        stdout=stdout,
                        stderr=stderr,
                    ),
                    cause=None,
                    started=started,
                    phase="waiting",
                    scanner=scanner_name,
                    target=target_name,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=False,
                    error_type="ScannerFailureError",
                    original_error=self._format_failure(
                        exit_code=exit_code,
                        stdout=stdout,
                        stderr=stderr,
                    ),
                )

            return result

        finally:
            self._cleanup_container(container)

    def _wait_for_exit(self, container, timeout: int, started: float) -> dict:
        """
        Poll container state instead of streaming container.wait().

        Long HTTP waits through a Docker socket proxy can fail with
        ChunkedEncodingError / ProtocolError even while the scanner
        is still running.
        """

        deadline = started + timeout

        while True:
            container.reload()
            state = (getattr(container, "attrs", None) or {}).get("State") or {}
            status = (container.status or state.get("Status") or "").lower()

            if status in self.TERMINAL_STATES:
                exit_code = state.get("ExitCode", 1)
                if exit_code is None:
                    exit_code = 1
                return {"StatusCode": int(exit_code)}

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Scanner timed out after {timeout} seconds."
                )

            remaining = deadline - time.monotonic()
            time.sleep(min(self.POLL_INTERVAL, max(remaining, 0)))

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
        if isinstance(exc, (TimeoutError, ReadTimeout, Urllib3ReadTimeoutError)):
            return True

        for error in self._walk_exceptions(exc):
            name = type(error).__name__.lower()
            if "timeout" in name or "timedout" in name:
                return True

            message = str(error).lower()
            if "timed out" in message or "timeout" in message:
                return True

        return False

    def _is_transport_error(self, exc: Exception) -> bool:
        transport_types = (
            ChunkedEncodingError,
            ProtocolError,
            ConnectionError,
            ConnectionResetError,
            BrokenPipeError,
        )

        for error in self._walk_exceptions(exc):
            if isinstance(
                error,
                (TimeoutError, ReadTimeout, Urllib3ReadTimeoutError),
            ):
                continue
            if isinstance(error, transport_types):
                return True

            name = type(error).__name__
            if name in {
                "ChunkedEncodingError",
                "ProtocolError",
                "ConnectionError",
                "ConnectionResetError",
                "RemoteDisconnected",
                "BrokenPipeError",
                "IncompleteRead",
            }:
                return True

        return False

    def _walk_exceptions(self, exc: BaseException):
        seen = set()
        current = exc

        while current is not None and id(current) not in seen:
            seen.add(id(current))
            yield current
            current = current.__cause__ or current.__context__

    def _exception_details(self, exc: BaseException | None) -> tuple[str, str]:
        if exc is None:
            return "ScannerExecutionError", ""

        types = []
        messages = []

        for error in self._walk_exceptions(exc):
            types.append(type(error).__name__)
            messages.append(str(error) or type(error).__name__)

        error_type = types[0]
        for name in types:
            if name in {"ChunkedEncodingError", "ProtocolError"}:
                error_type = name
                break

        original = " | ".join(
            f"{name}: {message}"
            for name, message in zip(types, messages)
        )
        return error_type, original

    def _duration(self, started: float) -> float:
        return round(time.monotonic() - started, 3)

    def _build_error(
        self,
        error_cls,
        message: str,
        *,
        cause: BaseException | None,
        started: float,
        phase: str,
        scanner: str,
        target: str,
        exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
        duration: float | None = None,
        error_type: str | None = None,
        original_error: str | None = None,
    ):
        resolved_type, resolved_original = self._exception_details(cause)
        error_type = error_type or resolved_type
        original_error = original_error or resolved_original
        duration = (
            duration if duration is not None else self._duration(started)
        )
        detail = message.rstrip(".")
        if original_error:
            detail = f"{detail}: {original_error}"

        full_message = (
            f"{detail} "
            f"(scanner={scanner}, target={target}, phase={phase}, "
            f"elapsed={duration}s, error_type={error_type})"
        )

        return error_cls(
            self._safe_message(full_message),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration=duration,
            scanner=scanner,
            target=target,
            phase=phase,
            error_type=error_type,
            original_error=original_error,
        )

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
        lowered = redacted.lower()

        for token in (
            "password=",
            "secret=",
            "token=",
            "api_key",
            "authorization:",
        ):
            if token in lowered:
                redacted = (
                    "Scanner execution failed. "
                    "See scanner logs for details."
                )
                break

        return self._truncate(redacted)
