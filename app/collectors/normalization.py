import json

from app.execution.protocol import ExecutionResult


class ObservationNormalizer:
    def normalize(self, result: ExecutionResult) -> dict[str, object]:
        content_type_header = result.headers.get("content-type")
        content_type = content_type_header.split(";", 1)[0].strip() if content_type_header else None
        json_type: str | None = None
        is_json = False
        try:
            parsed = json.loads(result.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        else:
            is_json = True
            json_type = self._json_type(parsed)
        return {
            "status_code": result.status_code,
            "content_type": content_type,
            "body_length": result.body_bytes,
            "redirect_location": result.headers.get("location"),
            "server": result.headers.get("server"),
            "is_json": is_json,
            "json_top_level_type": json_type,
            "truncated": result.truncated,
            "response_hash": result.evidence_sha256,
        }

    @staticmethod
    def _json_type(value: object) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        if isinstance(value, str):
            return "string"
        return "number"
