import json

import pytest
from uuid import uuid4

from app.domain.research import TargetScope
from app.domain.web_surface import AssessmentSeverity, ContentSource
from app.domain.common import Provenance
from app.web_surface.pipeline import WebSurfacePipeline
from app.web_surface.observations import traffic_observations
from app.system_model.mapper import WebSurfaceObservationMapper


def _burp_item(url: str, response_body: str = "<html></html>") -> bytes:
    request = "GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: secret\r\n\r\n"
    response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: secret\r\n\r\n{response_body}"
    import base64

    return f"""<items><item>
      <time>2026-08-25T10:00:00Z</time><url>{url}</url><method>GET</method>
      <status>200</status><mimetype>HTML</mimetype>
      <request base64="true">{base64.b64encode(request.encode()).decode()}</request>
      <response base64="true">{base64.b64encode(response.encode()).decode()}</response>
    </item></items>""".encode()


def _scope() -> TargetScope:
    return TargetScope(
        hosts=("example.test",),
        ports=(443,),
        schemes=("https",),
        provenance=Provenance(source_type="test", source_reference="web-surface"),
    )


def test_burp_traffic_builds_deduplicated_in_scope_surface_and_redacts_secrets() -> None:
    raw = _burp_item(
        "https://example.test/",
        '<html><a href="/admin">Admin</a><a href="https://outside.test/x">x</a>'
        '<form method="post" action="/login"></form></html>',
    )
    snapshot = WebSurfacePipeline().build(scope=_scope(), burp_export=raw)

    assert len(snapshot.traffic) == 1
    assert snapshot.traffic[0].request_headers["Authorization"] == "<redacted>"
    assert snapshot.traffic[0].response_headers["Set-Cookie"] == "<redacted>"
    assert [(item.method, item.path, item.source) for item in snapshot.content] == [
        ("GET", "/", ContentSource.TRAFFIC),
        ("GET", "/admin", ContentSource.HTML_LINK),
        ("POST", "/login", ContentSource.HTML_FORM),
    ]


def test_out_of_scope_burp_item_and_xml_entities_fail_closed() -> None:
    snapshot = WebSurfacePipeline().build(
        scope=_scope(), burp_export=_burp_item("https://outside.test/")
    )
    assert snapshot.traffic == ()
    assert snapshot.ignored_out_of_scope == 1
    with pytest.raises(ValueError, match="DTD"):
        WebSurfacePipeline().build(
            scope=_scope(),
            burp_export=b'<!DOCTYPE items [<!ENTITY x SYSTEM "file:///etc/passwd">]><items/>',
        )


def test_template_results_are_candidate_only_and_cannot_expand_scope() -> None:
    result = {
        "template-id": "missing-security-headers",
        "info": {"name": "Missing headers", "severity": "medium"},
        "matcher-name": "header-check",
        "matched-at": "https://example.test/admin",
        "type": "http",
        "timestamp": "2026-08-25T10:01:00Z",
    }
    snapshot = WebSurfacePipeline().build(
        scope=_scope(), burp_export=b"<items/>", template_results=json.dumps(result).encode()
    )
    assert snapshot.assessments[0].severity is AssessmentSeverity.MEDIUM
    assert snapshot.assessments[0].candidate_only is True
    assert snapshot.content[0].source is ContentSource.TEMPLATE_RESULT

    result["matched-at"] = "https://outside.test/admin"
    snapshot = WebSurfacePipeline().build(
        scope=_scope(), burp_export=b"<items/>", template_results=json.dumps(result).encode()
    )
    assert snapshot.assessments == ()
    assert snapshot.ignored_out_of_scope == 1


def test_burp_exchange_projects_to_observation_and_system_model_input() -> None:
    snapshot = WebSurfacePipeline().build(
        scope=_scope(), burp_export=_burp_item("https://example.test/admin")
    )
    artifact_id = uuid4()
    observations = traffic_observations(
        snapshot.traffic,
        asset_id=uuid4(),
        research_session_id=uuid4(),
        tool_artifact_id=artifact_id,
        artifact_sha256="a" * 64,
    )
    observation = observations[0]
    assert observation.tool_artifact_id == artifact_id
    assert "response_body" not in observation.normalized_data
    mapped = WebSurfaceObservationMapper().map(observation)
    assert (mapped.method, mapped.path, mapped.status_code) == ("GET", "/admin", 200)
