from unittest.mock import MagicMock

import pytest
from docker.errors import ImageNotFound
from requests.exceptions import ChunkedEncodingError
from urllib3.exceptions import ProtocolError

from app.scanner.docker_runner import (
    DockerRunner,
    DockerRunnerError,
    ScannerFailureError,
    ScannerTimeoutError,
)


def _container(
    stdout=b"ok\n",
    stderr=b"",
    status_code=0,
    status="exited",
):
    container = MagicMock()
    container.status = status
    container.attrs = {
        "State": {
            "Status": status,
            "ExitCode": status_code,
        }
    }
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
    container.reload.assert_called()
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


def test_timeout_kills_container_and_raises_timeout_error(monkeypatch):
    container = _container(
        stdout=b"partial",
        stderr=b"",
        status="running",
    )
    client = MagicMock()
    client.containers.run.return_value = container
    monkeypatch.setattr(DockerRunner, "POLL_INTERVAL", 0)

    with pytest.raises(ScannerTimeoutError) as exc_info:
        DockerRunner(client=client).run(
            image="vapt-tls:latest",
            command=["internal.test"],
            timeout=0,
        )

    error = exc_info.value
    assert error.timed_out is True
    assert "timed out" in str(error).lower()
    assert error.phase == "waiting"
    assert error.scanner == "vapt-tls:latest"
    assert error.target == "internal.test"
    container.kill.assert_called()
    container.remove.assert_called_with(force=True)


def test_chunked_encoding_error_becomes_runner_error_and_cleans_up():
    container = _container(status="running")
    container.reload.side_effect = ChunkedEncodingError(
        "Response ended prematurely"
    )
    client = MagicMock()
    client.containers.run.return_value = container

    with pytest.raises(DockerRunnerError) as exc_info:
        DockerRunner(client=client).run(
            image="vapt-tls:latest",
            command=["example.com"],
            timeout=30,
        )

    error = exc_info.value
    message = str(error)
    assert "ChunkedEncodingError" in message
    assert "Response ended prematurely" in message
    assert "phase=waiting" in message
    assert "scanner=vapt-tls:latest" in message
    assert "target=example.com" in message
    assert error.error_type == "ChunkedEncodingError"
    assert error.phase == "waiting"
    assert error.timed_out is False
    container.kill.assert_called()
    container.remove.assert_called_with(force=True)


def test_protocol_error_is_not_hidden():
    container = _container(status="running")
    container.reload.side_effect = ProtocolError("Connection broken")
    client = MagicMock()
    client.containers.run.return_value = container

    with pytest.raises(DockerRunnerError) as exc_info:
        DockerRunner(client=client).run(
            image="vapt-tls:latest",
            command=["example.com"],
        )

    error = exc_info.value
    assert "ProtocolError" in str(error)
    assert "Connection broken" in str(error)
    assert error.error_type == "ProtocolError"
    container.remove.assert_called_with(force=True)


def test_connection_reset_becomes_runner_error_and_cleans_up():
    container = _container(status="running")
    container.reload.side_effect = ConnectionResetError("Connection reset by peer")
    client = MagicMock()
    client.containers.run.return_value = container

    with pytest.raises(DockerRunnerError) as exc_info:
        DockerRunner(client=client).run(
            image="vapt-tls:latest",
            command=["example.com"],
        )

    error = exc_info.value
    assert "ConnectionResetError" in str(error)
    assert error.timed_out is False
    container.remove.assert_called_with(force=True)


def test_docker_startup_failure_raises_runner_error():
    client = MagicMock()
    client.containers.run.side_effect = ImageNotFound(
        "No such image: missing:latest"
    )

    with pytest.raises(DockerRunnerError) as exc_info:
        DockerRunner(client=client).run(
            image="missing:latest",
            command=["--help"],
        )

    error = exc_info.value
    assert "was not found" in str(error)
    assert error.phase == "starting"
    assert error.error_type == "ImageNotFound"


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
