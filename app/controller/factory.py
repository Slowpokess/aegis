from app.collectors.pipeline import ObservationPipeline
from app.config import Settings
from app.controller.acquisition import EvidenceAcquirer
from app.controller.context import ControllerContextBuilder
from app.controller.engine import ClosedLoopResearchController
from app.discovery.engine import DiscoveryEngine
from app.discovery.policy import ToolPolicy
from app.discovery.registry import ToolRegistry
from app.execution.experiments import ExperimentRunner
from app.execution.rust_executor import RustExecutorClient
from app.execution.rust_policy import RustPolicyClient
from app.llm.base import LLMProvider
from app.research_planner.resolver import ToolResolver
from app.research_strategy.strategy import ResearchStrategyEngine
from app.storage.database import Database
from app.verification.verifier import VerificationEngine


def build_controller(
    database: Database,
    settings: Settings,
    *,
    provider: LLMProvider | None = None,
    registry: ToolRegistry | None = None,
) -> ClosedLoopResearchController:
    registry = registry or ToolRegistry(
        enabled={
            "nmap": settings.nmap_enabled,
            "ffuf": settings.ffuf_enabled,
            "nuclei": settings.nuclei_enabled,
        }
    )
    executor = RustExecutorClient(
        settings.executor_path,
        process_grace_seconds=settings.executor_process_grace_seconds,
    )
    pipeline = ObservationPipeline(database, executor)
    policy_client = RustPolicyClient(settings.policy_path, settings.policy_process_timeout_seconds)
    discovery = DiscoveryEngine(
        database,
        registry,
        pipeline,
        artifact_max_bytes=settings.tool_artifact_max_bytes,
        max_concurrency=settings.tool_max_concurrency,
        max_runs_per_plan=settings.tool_max_runs_per_plan,
    )
    experiment_runner = ExperimentRunner(database, policy_client, pipeline, settings)
    strategy = ResearchStrategyEngine(
        database,
        ToolResolver(registry, ToolPolicy(registry)),
        minimum_verification_runs=settings.min_verification_runs,
        max_selected_intents=settings.strategy_max_selected_intents,
    )
    context = ControllerContextBuilder(
        database,
        max_bytes=settings.controller_max_context_bytes,
        max_entities=settings.controller_max_entities,
        max_gaps=settings.controller_max_gaps,
        max_signals=settings.controller_max_signals,
        max_history=settings.controller_max_history,
        max_hypotheses=settings.controller_max_hypotheses,
    )
    return ClosedLoopResearchController(
        database,
        settings,
        strategy,
        context,
        EvidenceAcquirer(
            database,
            settings,
            registry,
            pipeline,
            policy_client,
            discovery,
            experiment_runner,
            VerificationEngine(database, min_verification_runs=settings.min_verification_runs),
        ),
        provider=provider,
        max_actions_per_step=settings.controller_max_actions_per_step,
    )
