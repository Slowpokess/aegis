from app.domain.discovery import ToolErrorCode


class ToolExecutionError(RuntimeError):
    def __init__(self, code: ToolErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)
