from collections.abc import Iterator
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from app.storage.database import Database


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark only tests that really request the loopback laboratory fixture."""
    for item in items:
        if "live_lab" in getattr(item, "fixturenames", ()):
            item.add_marker(pytest.mark.network_integration)


@pytest.fixture
def database(tmp_path) -> Iterator[Database]:
    database = Database(f"sqlite:///{tmp_path / 'test.db'}")
    database.create_schema()
    try:
        yield database
    finally:
        database.dispose()


@pytest.fixture
def live_lab() -> Iterator[int]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "lab.vulnerable_api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2)
            except OSError:
                time.sleep(0.05)
            else:
                break
        else:
            raise RuntimeError("local laboratory did not start")
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
