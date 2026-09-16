from time import monotonic
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.experiments import Experiment, ExperimentStatus
from app.domain.llm_runs import LLMRun, LLMRunPurpose, LLMRunStatus
from app.llm.base import LLMMessage, LLMProvider, LLMProviderError, LLMRequestMetadata, LLMRole
from app.logging_config import experiment_log
from app.reasoning.experiment_context import ExperimentContextBuilder
from app.reasoning.experiment_schemas import ExperimentProposal
from app.reasoning.experiment_validation import ExperimentValidation, ExperimentValidator
from app.reasoning.prompts import PromptBundle, load_experiment_prompt
from app.storage.database import Database
from app.storage.repositories import RepositorySet


class ExperimentEngineResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    llm_run: LLMRun
    experiment: Experiment
    validation: ExperimentValidation


class ExperimentEngine:
    def __init__(
        self,
        database: Database,
        provider: LLMProvider,
        *,
        context_builder: ExperimentContextBuilder | None = None,
        validator: ExperimentValidator | None = None,
        prompt: PromptBundle | None = None,
    ) -> None:
        self.database = database
        self.provider = provider
        self.context_builder = context_builder or ExperimentContextBuilder(database)
        self.validator = validator or ExperimentValidator()
        self.prompt = prompt or load_experiment_prompt()

    async def generate(self, hypothesis_id: UUID) -> ExperimentEngineResult:
        context = self.context_builder.build(hypothesis_id)
        llm_run = LLMRun(
            research_session_id=context.research_session_id,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            prompt_version=self.prompt.version,
            purpose=LLMRunPurpose.EXPERIMENT_GENERATION,
            context_sha256=context.sha256,
            provenance=Provenance(
                source_type="llm-reasoning",
                source_reference=f"experiment-context:{context.sha256}",
                collector="aegis-experiment-engine",
                classification=FactClassification.INFERRED,
            ),
        )
        with self.database.session_factory.begin() as session:
            RepositorySet(session).llm_runs.add(llm_run)
        started = monotonic()
        messages = [
            LLMMessage(role=LLMRole.SYSTEM, content=self.prompt.system),
            LLMMessage(
                role=LLMRole.USER,
                content=(
                    f"{self.prompt.task}\n\n<UNTRUSTED_TARGET_DATA_CONTEXT>\n"
                    f"{context.canonical_json}\n</UNTRUSTED_TARGET_DATA_CONTEXT>"
                ),
            ),
        ]
        try:
            generation = await self.provider.structured_generate(
                messages=messages,
                response_model=ExperimentProposal,
                metadata=LLMRequestMetadata(
                    run_id=llm_run.id,
                    prompt_version=self.prompt.version,
                    context_sha256=context.sha256,
                ),
            )
        except LLMProviderError as error:
            failed = LLMRun.model_validate(
                {
                    **llm_run.model_dump(mode="python"),
                    "status": LLMRunStatus.FAILED,
                    "completed_at": utc_now(),
                    "latency_ms": round((monotonic() - started) * 1000),
                    "attempts": error.attempts,
                    "error_code": error.code.value,
                }
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).llm_runs.update(failed)
            raise
        validation = self.validator.validate(generation.output, allowed_paths=context.allowed_paths)
        experiment = Experiment(
            research_session_id=context.research_session_id,
            hypothesis_id=hypothesis_id,
            description=generation.output.description,
            changed_variable=generation.output.changed_variable,
            constants=generation.output.constants,
            preconditions=generation.output.preconditions,
            candidate=generation.output.candidate,
            control=generation.output.control,
            expected_if_true=generation.output.expected_if_true,
            expected_if_false=generation.output.expected_if_false,
            risk=generation.output.risk,
            status=ExperimentStatus.VALIDATED if validation.valid else ExperimentStatus.DRAFT,
            llm_run_id=llm_run.id,
            validation_errors=validation.errors,
            verification_spec=generation.output.verification_spec,
            provenance=Provenance(
                source_type="llm-reasoning",
                source_reference=str(llm_run.id),
                collector=self.provider.provider_name,
                classification=FactClassification.INFERRED,
                metadata={"prompt_version": self.prompt.version, "context_sha256": context.sha256},
            ),
        )
        usage = generation.metadata.usage
        completed = LLMRun.model_validate(
            {
                **llm_run.model_dump(mode="python"),
                "provider": generation.metadata.provider,
                "model": generation.metadata.model,
                "provider_request_id": generation.metadata.provider_request_id,
                "completed_at": generation.metadata.completed_at,
                "status": LLMRunStatus.COMPLETED,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.total_tokens,
                "latency_ms": generation.metadata.latency_ms,
                "attempts": generation.metadata.attempts,
                "generated_count": 1,
                "accepted_count": int(validation.valid),
                "rejected_count": int(not validation.valid),
                "validation_rejections": validation.errors,
            }
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.experiments.add(experiment)
            repositories.llm_runs.update(completed)
        experiment_log.info(
            "experiment generated experiment_id=%s hypothesis_id=%s status=%s",
            experiment.id,
            hypothesis_id,
            experiment.status.value,
        )
        return ExperimentEngineResult(llm_run=completed, experiment=experiment, validation=validation)
