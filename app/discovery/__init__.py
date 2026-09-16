__all__ = ["DiscoveryEngine", "ToolRegistry"]


def __getattr__(name: str):
    if name == "DiscoveryEngine":
        from app.discovery.engine import DiscoveryEngine

        return DiscoveryEngine
    if name == "ToolRegistry":
        from app.discovery.registry import ToolRegistry

        return ToolRegistry
    raise AttributeError(name)
