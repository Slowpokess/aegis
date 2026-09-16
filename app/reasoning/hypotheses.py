from uuid import UUID
from time import monotonic

from pydantic import BaseModel, ConfigDict

from app.domain.common import FactClassification, Provenance, utc_now
from app.domain.hypotheses import Hypothesis, HypothesisStatus, MissingInformation
from app.domain.llm_runs import LLMRun, LLMRunStatus
from app.llm.base import (
    LLMMessage,
    LLMProvider,
    LLMProviderError,
    LLMRequestMetadata,
    LLMRole,
)
from app.logging_config import llm_log
from app.reasoning.context import ContextBuildResult, HypothesisContextBuilder
from app.reasoning.prompts import PromptBundle, load_hypothesis_prompt
from app.reasoning.schemas import HypothesisBatch
from app.reasoning.validation import HypothesisRejection, HypothesisValidator
from app.storage.database import Database
from app.storage.repositories import RepositorySet


class EngineModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HypothesisEngineResult(EngineModel):
    llm_run: LLMRun
    hypotheses: list[Hypothesis]
    rejections: list[HypothesisRejection]
    context_observation_count: int


class HypothesisEngine:
    def __init__(
        self,
        database: Database,
        provider: LLMProvider,
        *,
        context_builder: HypothesisContextBuilder | None = None,
        validator: HypothesisValidator | None = None,
        prompt: PromptBundle | None = None,
        max_hypotheses: int = 5,
    ) -> None:
        self.database = database
        self.provider = provider
        self.context_builder = context_builder or HypothesisContextBuilder(database)
        self.validator = validator or HypothesisValidator()
        self.prompt = prompt or load_hypothesis_prompt()
        self.max_hypotheses = max_hypotheses

    async def generate(self, research_session_id: UUID) -> HypothesisEngineResult:
        context_result = self.context_builder.build(research_session_id)
        llm_run = LLMRun(
            research_session_id=research_session_id,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            prompt_version=self.prompt.version,
            context_sha256=context_result.sha256,
            context_observation_ids=[
                item.observation_id for item in context_result.context.observations
            ],
            provenance=Provenance(
                source_type="llm-reasoning",
                source_reference=f"context:{context_result.sha256}",
                collector="aegis-hypothesis-engine",
                classification=FactClassification.INFERRED,
            ),
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            if repositories.research_sessions.get(research_session_id) is None:
                raise ValueError("research session does not exist")
            repositories.llm_runs.add(llm_run)
        llm_log.info(
            "LLM run started run_id=%s provider=%s model=%s prompt=%s",
            llm_run.id,
            llm_run.provider,
            llm_run.model,
            llm_run.prompt_version,
        )
        messages = self._messages(context_result)
        provider_started = monotonic()
        try:
            generation = await self.provider.structured_generate(
                messages=messages,
                response_model=HypothesisBatch,
                metadata=LLMRequestMetadata(
                    run_id=llm_run.id,
                    prompt_version=self.prompt.version,
                    context_sha256=context_result.sha256,
                ),
            )
        except LLMProviderError as error:
            failed = LLMRun.model_validate(
                {
                    **llm_run.model_dump(mode="python"),
                    "status": LLMRunStatus.FAILED,
                    "completed_at": utc_now(),
                    "attempts": error.attempts,
                    "error_code": error.code.value,
                    "latency_ms": round((monotonic() - provider_started) * 1000),
                }
            )
            with self.database.session_factory.begin() as session:
                RepositorySet(session).llm_runs.update(failed)
            llm_log.warning(
                "LLM run failed run_id=%s provider=%s model=%s prompt=%s status=%s",
                failed.id,
                failed.provider,
                failed.model,
                failed.prompt_version,
                failed.error_code,
            )
            raise

        with self.database.session_factory() as session:
            repositories = RepositorySet(session)
            all_observations = repositories.observations.list()
            all_evidence = repositories.evidence.list()
            existing = repositories.hypotheses.list_by_session(research_session_id)
        validation = self.validator.validate(
            batch=generation.output,
            research_session_id=research_session_id,
            observations=all_observations,
            evidence=all_evidence,
            existing_hypotheses=existing,
            max_hypotheses=self.max_hypotheses,
        )
        hypotheses = [self._to_domain(candidate, llm_run) for candidate in validation.accepted]
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
                "generated_count": len(generation.output.hypotheses),
                "accepted_count": len(hypotheses),
                "rejected_count": len(validation.rejected),
                "validation_rejections": [
                    item.model_dump(mode="json") for item in validation.rejected
                ],
            }
        )
        with self.database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            for hypothesis in hypotheses:
                repositories.hypotheses.add(hypothesis)
            repositories.llm_runs.update(completed)
        llm_log.info(
            "LLM run completed run_id=%s provider=%s model=%s prompt=%s latency_ms=%s "
            "generated=%s accepted=%s rejected=%s",
            completed.id,
            completed.provider,
            completed.model,
            completed.prompt_version,
            completed.latency_ms,
            completed.generated_count,
            completed.accepted_count,
            completed.rejected_count,
        )
        return HypothesisEngineResult(
            llm_run=completed,
            hypotheses=hypotheses,
            rejections=validation.rejected,
            context_observation_count=len(context_result.context.observations),
        )

    def _messages(self, context: ContextBuildResult) -> list[LLMMessage]:
        user_content = (
            f"{self.prompt.task}\n\n"
            "<UNTRUSTED_TARGET_DATA_CONTEXT>\n"
            f"{context.canonical_json}\n"
            "</UNTRUSTED_TARGET_DATA_CONTEXT>"
        )
        return [
            LLMMessage(role=LLMRole.SYSTEM, content=self.prompt.system),
            LLMMessage(role=LLMRole.USER, content=user_content),
        ]

    @staticmethod
    def _to_domain(candidate: object, llm_run: LLMRun) -> Hypothesis:
        from app.reasoning.schemas import HypothesisCandidate

        parsed = HypothesisCandidate.model_validate(candidate)
        return Hypothesis(
            research_session_id=llm_run.research_session_id,
            llm_run_id=llm_run.id,
            title=parsed.title,
            description=parsed.description,
            observation_ids=parsed.observation_ids,
            evidence_ids=parsed.evidence_ids,
            assumptions=parsed.assumptions,
            missing_information=[
                MissingInformation(
                    description=item.description,
                    related_observation_ids=item.related_observation_ids,
                )
                for item in parsed.missing_information
            ],
            confidence=parsed.confidence,
            status=HypothesisStatus.NEW,
            provenance=Provenance(
                source_type="llm-reasoning",
                source_reference=str(llm_run.id),
                collector=llm_run.provider,
                classification=FactClassification.INFERRED,
                metadata={
                    "llm_run_id": str(llm_run.id),
                    "prompt_version": llm_run.prompt_version,
                    "context_sha256": llm_run.context_sha256,
                },
            ),
        )
