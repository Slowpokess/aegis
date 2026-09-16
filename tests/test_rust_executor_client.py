import stat
from pathlib import Path

import pytest

from app.execution.protocol import ErrorCode, ExecutorRequest
from app.execution.rust_executor import ExecutorClientError, RustExecutorClient


def executable(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake-executor"
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def request() -> ExecutorRequest:
    return ExecutorRequest(request_id="REQ-TEST", method="GET", url="http://127.0.0.1/")


@pytest.mark.asyncio
async def test_missing_executor_is_typed(tmp_path: Path) -> None:
    client = RustExecutorClient(tmp_path / "missing")
    with pytest.raises(ExecutorClientError) as captured:
        await client.execute(request())
    assert captured.value.code is ErrorCode.EXECUTOR_NOT_FOUND


@pytest.mark.asyncio
async def test_invalid_stdout_is_typed(tmp_path: Path) -> None:
    client = RustExecutorClient(executable(tmp_path, "printf 'not-json'"))
    with pytest.raises(ExecutorClientError) as captured:
        await client.execute(request())
    assert captured.value.code is ErrorCode.SERIALIZATION_ERROR


@pytest.mark.asyncio
async def test_protocol_mismatch_is_typed(tmp_path: Path) -> None:
    response = '{"protocol_version":2,"ok":false}'
    client = RustExecutorClient(executable(tmp_path, f"printf '{response}'"))
    with pytest.raises(ExecutorClientError) as captured:
        await client.execute(request())
    assert captured.value.code is ErrorCode.UNSUPPORTED_PROTOCOL_VERSION


@pytest.mark.asyncio
async def test_executor_process_timeout_is_typed(tmp_path: Path) -> None:
    client = RustExecutorClient(executable(tmp_path, "sleep 1"), process_grace_seconds=0.1)
    operation = request().model_copy(update={"timeout_ms": 1})
    with pytest.raises(ExecutorClientError) as captured:
        await client.execute(operation)
    assert captured.value.code is ErrorCode.TIMEOUT
