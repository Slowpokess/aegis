from app.discovery.sdk import ToolIntegration
from app.domain.discovery import ToolRequest


def assert_integration_contract(integration: ToolIntegration) -> None:
    integration.validate()
    assert integration.request_schema is ToolRequest
    assert integration.descriptor.id
    assert integration.profiles
    assert not hasattr(integration.request_schema, "shell")
