from unittest.mock import MagicMock

import pytest
from docker.errors import ImageNotFound

from app.scanner.docker_runner import (
    DockerRunner,
    DockerRunnerError,
    ScannerFailureError,
    ScannerTimeoutError,
)


def _container(stdout=b"ok\n", stderr=b"", status_code=0):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": status_code}
    stdout_bytes = stdout
    stderr_bytes = stderr

    def logs(*, stdout=True, stderr=True):
        if stdout and not stderr:
            return stdout_bytes
        if stderr and not stdout:
            return stderr_bytes
        return stdout_bytes + stderr_bytes

    container.logs.side_effect = logs
    return container


def test_successful_container_execution_returns_stdout():
    container = _container(stdout=b"report xml", stderr=b"warn")
    client = MagicMock()
    client.containers.run.return_value = container

    output = DockerRunner(client=client).run(
        image="vapt-nmap:latest",
        command=["-sV", "10.0.0.8"],
        timeout=30,
    )

    assert output == "report xml"
    container.remove.assert_called_with(force=True)


def test_run_detailed_separates_stdout_and_stderr():
    container = _container(stdout=b"out", stderr=b"err")
    client = MagicMock()
    client.containers.run.return_value = container

    result = DockerRunner(client=client).run_detailed(
        image="vapt-nmap:latest",
        command=["-sV", "10.0.0.8"],
    )

    assert result.stdout == "out"
    assert result.stderr == "err"
    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.duration >= 0


def test_non_zero_exit_raises_scanner_failure_and_cleans_up():
    container = _container(stdout=b"", stderr=b"boom", status_code=2)
    client = MagicMock()
    client.containers.run.return_value = container

    with pytest.raises(ScannerFailureError) as exc_info:
        DockerRunner(client=client).run(
            image="vapt-nikto:latest",
            command=["-h", "https://internal.test"],
        )

    assert exc_info.value.exit_code == 2
    assert exc_info.value.stderr == "boom"
    assert exc_info.value.timed_out is False
    container.remove.assert_called_with(force=True)


def test_timeout_kills_container_and_raises_timeout_error():
    container = _container(stdout=b"partial", stderr=b"")
    container.wait.side_effect = TimeoutError("Read timed out")
    client = MagicMock()
    client.containers.run.return_value = container

    with pytest.raises(ScannerTimeoutError) as exc_info:
        DockerRunner(client=client).run(
            image="vapt-tls:latest",
            command=["internal.test"],
            timeout=1,
        )

    assert exc_info.value.timed_out is True
    assert "timed out" in str(exc_info.value).lower()
    container.kill.assert_called()
    container.remove.assert_called_with(force=True)


def test_docker_startup_failure_raises_runner_error():
    client = MagicMock()
    client.containers.run.side_effect = ImageNotFound(
        "No such image: missing:latest"
    )

    with pytest.raises(DockerRunnerError, match="was not found"):
        DockerRunner(client=client).run(
            image="missing:latest",
            command=["--help"],
        )


def test_cleanup_happens_when_logs_fail_after_success_wait():
    container = _container()
    container.logs.side_effect = RuntimeError("cannot read logs")
    client = MagicMock()
    client.containers.run.return_value = container

    output = DockerRunner(client=client).run(
        image="vapt-nmap:latest",
        command=["-sV", "10.0.0.8"],
    )

    assert output == ""
    container.remove.assert_called_with(force=True)
