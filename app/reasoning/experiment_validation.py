from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from app.domain.experiments import HTTPExperimentAction, RiskLevel
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.protocol import SENSITIVE_HEADERS
from app.reasoning.experiment_schemas import ExperimentProposal
from app.domain.verification import ComparisonType

ALLOWED_MODEL_HEADERS = frozenset({"accept", "accept-language"})
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ExperimentValidation(BaseModel):
    model_config = ConfigDict(frozen=True)
    valid: bool
    errors: list[dict[str, str]]


class ExperimentValidator:
    def __init__(self, identity_resolver: LaboratoryIdentityResolver | None = None) -> None:
        self.identity_resolver = identity_resolver or LaboratoryIdentityResolver()

    def validate(
        self, proposal: ExperimentProposal, *, allowed_paths: frozenset[str]
    ) -> ExperimentValidation:
        errors: list[dict[str, str]] = []
        if proposal.risk not in {RiskLevel.PASSIVE, RiskLevel.LOW}:
            errors.append({"code": "RISK_NOT_ALLOWED", "message": "only read-only risk is allowed"})
        for role, action in (("candidate", proposal.candidate), ("control", proposal.control)):
            self._validate_action(role, action, allowed_paths, errors)
        if proposal.candidate == proposal.control:
            errors.append(
                {"code": "CONTROL_NOT_FALSIFYING", "message": "control must differ from candidate"}
            )
        if proposal.verification_spec is not None and not proposal.verification_spec.has_required_impact:
            errors.append(
                {
                    "code": "VERIFICATION_IMPACT_REQUIRED",
                    "message": "verification spec requires an observable-impact comparison",
                }
            )
        if proposal.verification_spec is not None and any(
            item.impact and item.type is ComparisonType.STATUS_CODE
            for item in proposal.verification_spec.comparisons
        ):
            errors.append(
                {
                    "code": "STATUS_NOT_OBSERVABLE_IMPACT",
                    "message": "status code alone cannot establish observable security impact",
                }
            )
        return ExperimentValidation(valid=not errors, errors=errors)

    def _validate_action(
        self,
        role: str,
        action: HTTPExperimentAction,
        allowed_paths: frozenset[str],
        errors: list[dict[str, str]],
    ) -> None:
        parsed = urlsplit(action.path)
        if (
            not action.path.startswith("/")
            or action.path.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
        ):
            errors.append({"code": "INVALID_PATH", "message": f"{role} path must be relative to target"})
        elif parsed.path not in allowed_paths:
            errors.append({"code": "PATH_NOT_GROUNDED", "message": f"{role} path is not grounded"})
        if action.identity not in self.identity_resolver.allowed_names:
            errors.append({"code": "IDENTITY_NOT_ALLOWED", "message": f"{role} identity is unknown"})
        if action.method.upper() not in ALLOWED_METHODS:
            errors.append({"code": "METHOD_NOT_ALLOWED", "message": f"{role} method is not read-only"})
        for header in action.headers:
            lowered = header.lower()
            if lowered in SENSITIVE_HEADERS or lowered not in ALLOWED_MODEL_HEADERS:
                errors.append({"code": "HEADER_NOT_ALLOWED", "message": f"{role} header is protected"})
