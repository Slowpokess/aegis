import json

from app.domain.active_web import FFUF_PARSER_VERSION, NUCLEI_PARSER_VERSION, FfufResultRecord
from app.domain.research import TargetScope
from app.domain.web_surface import TemplateAssessment
from app.web_surface.parsers import TemplateAssessmentParser


class FfufParser:
    version = FFUF_PARSER_VERSION

    def __init__(self, *, max_bytes: int, max_results: int) -> None:
        self.max_bytes = max_bytes
        self.max_results = max_results

    def parse(self, raw: bytes, scope: TargetScope) -> tuple[FfufResultRecord, ...]:
        if len(raw) > self.max_bytes:
            raise ValueError("ffuf artifact exceeds parser input bound")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("ffuf artifact is not valid JSON") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("ffuf artifact has an unsupported schema")
        if len(payload["results"]) > self.max_results:
            raise ValueError("ffuf result count exceeds configured bound")
        records: list[FfufResultRecord] = []
        for result in payload["results"]:
            if not isinstance(result, dict):
                raise ValueError("ffuf result must be a JSON object")
            url = result.get("url")
            status = result.get("status")
            if not isinstance(url, str) or not isinstance(status, int):
                raise ValueError("ffuf result is missing URL or status")
            try:
                scope.validate_url(url)
            except ValueError:
                continue
            redirect = result.get("redirectlocation")
            content_type = result.get("content-type") or result.get("content_type")
            records.append(
                FfufResultRecord(
                    url=url,
                    status_code=status,
                    content_length=_integer(result.get("length")),
                    content_words=_integer(result.get("words")),
                    content_lines=_integer(result.get("lines")),
                    redirect_location=redirect if isinstance(redirect, str) and redirect else None,
                    content_type=(
                        content_type if isinstance(content_type, str) and content_type else None
                    ),
                )
            )
        return tuple(sorted(records, key=lambda item: (item.url, item.status_code)))


class NucleiParser:
    version = NUCLEI_PARSER_VERSION

    def __init__(self, *, max_bytes: int, max_results: int) -> None:
        self.parser = TemplateAssessmentParser(
            max_bytes=max_bytes,
            max_records=max_results,
        )

    def parse(self, raw: bytes, scope: TargetScope) -> tuple[TemplateAssessment, ...]:
        return self.parser.parse(raw, scope)


def _integer(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0
