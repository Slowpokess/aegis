import asyncio
import json
from pathlib import Path

from pydantic import ValidationError

from app.execution.policy_protocol import PolicyRequest, PolicyResponse, PROTOCOL_VERSION
from app.logging_config import policy_log


class PolicyClientError(RuntimeError):
    pass


class RustPolicyClient:
    def __init__(self, binary_path: Path, process_timeout_seconds: float = 3.0) -> None:
        self.binary_path = binary_path
        self.process_timeout_seconds = process_timeout_seconds

    async def evaluate(self, request: PolicyRequest) -> PolicyResponse:
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.binary_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as error:
            raise PolicyClientError(f"Rust policy binary not found: {self.binary_path}") from error
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(request.model_dump_json().encode()),
                timeout=self.process_timeout_seconds,
            )
        except TimeoutError as error:
            process.kill()
            await process.wait()
            raise PolicyClientError("policy process timed out; action denied") from error
        if process.returncode != 0:
            diagnostic = stderr.decode(errors="replace").strip()
            raise PolicyClientError(
                f"policy process exited with code {process.returncode}: {diagnostic}"
            )
        try:
            raw = json.loads(stdout)
            response = PolicyResponse.model_validate(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as error:
            raise PolicyClientError("policy returned invalid structured output") from error
        if response.protocol_version != PROTOCOL_VERSION or response.decision_id != request.decision_id:
            raise PolicyClientError("policy response protocol or decision identifier mismatch")
        if response.policy_sha256 and response.policy_sha256 != request.policy.canonical_sha256():
            raise PolicyClientError("policy hash mismatch")
        policy_log.info(
            "policy decision_id=%s allowed=%s reason=%s",
            response.decision_id,
            response.allowed,
            response.reason_code.value,
        )
        return response
