from app.domain.attack_graph import GraphErrorCode


class AttackGraphError(RuntimeError):
    def __init__(self, code: GraphErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)
