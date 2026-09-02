from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def mock_docker_client(monkeypatch):
    monkeypatch.setattr(
        "app.scanner.docker_runner.docker.from_env",
        lambda: MagicMock(),
    )
