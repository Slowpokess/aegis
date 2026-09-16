import asyncio
import json
from pathlib import Path

from pydantic import ValidationError

from app.execution.protocol import (
    EXECUTOR_RESPONSE_ADAPTER,
    ErrorCode,
    ExecutorFailure,
    ExecutorRequest,
    ExecutorSuccess,
    PROTOCOL_VERSION,
)
from app.logging_config import execution_log


class ExecutorClientError(RuntimeError):
    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class RustExecutorClient:
    def __init__(self, binary_path: Path, process_grace_seconds: float = 2.0) -> None:
        self.binary_path = binary_path
        self.process_grace_seconds = process_grace_seconds

    async def execute(self, request: ExecutorRequest) -> ExecutorSuccess:
        execution_log.info("executor request started request_id=%s", request.request_id)
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.binary_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as error:
            raise ExecutorClientError(
                ErrorCode.EXECUTOR_NOT_FOUND,
                f"Rust executor binary not found: {self.binary_path}",
            ) from error

        timeout = request.timeout_ms / 1000 + self.process_grace_seconds
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(request.model_dump_json().encode()), timeout=timeout
            )
        except TimeoutError as error:
            process.kill()
            await process.wait()
            raise ExecutorClientError(
                ErrorCode.TIMEOUT, "executor process exceeded its transport timeout"
            ) from error

        if process.returncode != 0:
            diagnostic = stderr.decode(errors="replace").strip()
            raise ExecutorClientError(
                ErrorCode.EXECUTOR_PROCESS_ERROR,
                f"executor exited with code {process.returncode}: {diagnostic}",
            )
        try:
            raw_response = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ExecutorClientError(
                ErrorCode.SERIALIZATION_ERROR, "executor returned invalid protocol JSON"
            ) from error
        if raw_response.get("protocol_version") != PROTOCOL_VERSION:
            raise ExecutorClientError(
                ErrorCode.UNSUPPORTED_PROTOCOL_VERSION, "executor response protocol mismatch"
            )
        try:
            response = EXECUTOR_RESPONSE_ADAPTER.validate_python(raw_response)
        except ValidationError as error:
            raise ExecutorClientError(
                ErrorCode.SERIALIZATION_ERROR, "executor returned invalid protocol JSON"
            ) from error
        if isinstance(response, ExecutorFailure):
            raise ExecutorClientError(response.error.code, response.error.message)
        if response.request_id != request.request_id:
            raise ExecutorClientError(
                ErrorCode.SERIALIZATION_ERROR, "executor response request_id mismatch"
            )
        execution_log.info(
            "executor request completed request_id=%s status=%s",
            request.request_id,
            response.result.status_code,
        )
        return response
