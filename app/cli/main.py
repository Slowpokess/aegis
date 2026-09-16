import asyncio
import json
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

import typer
from sqlalchemy.engine import make_url

from app import __version__
from app.collectors.pipeline import ObservationPipeline
from app.config import get_settings
from app.domain.assets import Asset, AssetKind
from app.domain.common import FactClassification, Provenance
from app.domain.research import ResearchSession, ResearchTarget, TargetScope
from app.execution.protocol import HttpMethod, redact_headers
from app.execution.identity import LaboratoryIdentityResolver
from app.execution.rust_policy import RustPolicyClient
from app.execution.experiments import ExperimentRunner
from app.execution.rust_executor import RustExecutorClient
from app.llm.factory import create_llm_provider
from app.llm.base import LLMProviderError
from app.reasoning.context import HypothesisContextBuilder
from app.reasoning.hypotheses import HypothesisEngine
from app.reasoning.schemas import HypothesisBatch
from app.reasoning.experiment_schemas import ExperimentProposal
from app.reasoning.experiments import ExperimentEngine
from app.storage.database import Database
from app.storage.repositories import RepositorySet
from app.verification.verifier import VerificationEngine
from app.system_model.cli import model_cli
from app.attack_graph.cli import graph_cli
from app.discovery.cli import artifacts_cli, discover_cli, tool_runs_cli, tools_cli
from app.research_planner.cli import register_research_planner_commands
from app.research_strategy.cli import gaps_cli, knowledge_cli, strategy_cli
from app.controller.cli import controller_cli
from app.operator.cli import policies_cli, projects_cli, report_cli
from app.web_surface.cli import web_cli

cli = typer.Typer(help="Aegis local security research platform.", no_args_is_help=True)
research_cli = typer.Typer(help="Manage immutable research sessions.")
evidence_cli = typer.Typer(help="Inspect captured evidence.")
observations_cli = typer.Typer(help="Inspect normalized observations.")
hypotheses_cli = typer.Typer(help="Generate and inspect evidence-grounded hypotheses.")
experiments_cli = typer.Typer(help="Generate, policy-check, and explicitly run experiments.")
verify_cli = typer.Typer(help="Deterministically verify experiment evidence.")
findings_cli = typer.Typer(help="Inspect evidence-backed findings.")
cli.add_typer(research_cli, name="research")
cli.add_typer(evidence_cli, name="evidence")
cli.add_typer(observations_cli, name="observations")
cli.add_typer(hypotheses_cli, name="hypotheses")
cli.add_typer(experiments_cli, name="experiments")
cli.add_typer(verify_cli, name="verify")
cli.add_typer(findings_cli, name="findings")
cli.add_typer(model_cli, name="model")
cli.add_typer(graph_cli, name="graph")
cli.add_typer(tools_cli, name="tools")
cli.add_typer(discover_cli, name="discover")
cli.add_typer(tool_runs_cli, name="tool-runs")
cli.add_typer(artifacts_cli, name="artifacts")
cli.add_typer(knowledge_cli, name="knowledge")
cli.add_typer(gaps_cli, name="gaps")
cli.add_typer(strategy_cli, name="strategy")
cli.add_typer(controller_cli, name="controller")
cli.add_typer(projects_cli, name="projects")
cli.add_typer(policies_cli, name="policies")
cli.add_typer(report_cli, name="report")
cli.add_typer(web_cli, name="web")
register_research_planner_commands(research_cli)


@cli.command("info")
def info() -> None:
    """Print non-sensitive runtime information."""
    settings = get_settings()
    typer.echo(f"Aegis {__version__}")
    typer.echo(f"Environment: {settings.environment}")
    safe_database_url = make_url(settings.database_url).render_as_string(hide_password=True)
    typer.echo(f"Database: {safe_database_url}")
    typer.echo(f"Executor: {settings.executor_path}")
    typer.echo(f"Policy: {settings.policy_path}")
    typer.echo(f"LLM provider: {settings.llm_provider}")
    typer.echo(f"LLM model: {settings.llm_model}")


@cli.command("init-db")
def init_db(
    database_url: Annotated[
        str | None,
        typer.Option(help="Override the configured SQLAlchemy database URL."),
    ] = None,
) -> None:
    """Create the current database schema (idempotent)."""
    settings = get_settings()
    database = Database(database_url or settings.database_url)
    try:
        database.create_schema()
    finally:
        database.dispose()
    typer.echo("Database schema initialized.")


def _trusted_provenance(reference: str) -> Provenance:
    return Provenance(
        source_type="configuration",
        source_reference=reference,
        collector="aegis-cli",
        classification=FactClassification.OBSERVED,
    )


@research_cli.command("create")
def research_create(
    name: Annotated[str, typer.Option(help="Research session name.")],
    host: Annotated[str, typer.Option(help="Exact allowed target host.")],
    port: Annotated[int, typer.Option(help="Exact allowed target port.")],
    scheme: Annotated[str, typer.Option(help="Allowed HTTP scheme.")] = "http",
) -> None:
    """Create a session with an immutable single-target scope."""
    settings = get_settings()
    database = Database(settings.database_url)
    database.create_schema()
    provenance = _trusted_provenance("CLI research create")
    asset = Asset(name=name, kind=AssetKind.API, provenance=provenance)
    scope = TargetScope(hosts=(host,), ports=(port,), schemes=(scheme,), provenance=provenance)
    base_url = f"{scheme}://{host}:{port}"
    target = ResearchTarget(
        asset_id=asset.id,
        name=name,
        base_url=base_url,
        provenance=provenance,
    )
    research_session = ResearchSession(
        name=name,
        target=target,
        scope=scope,
        provenance=provenance,
    )
    try:
        with database.session_factory.begin() as session:
            repositories = RepositorySet(session)
            repositories.assets.add(asset)
            repositories.research_sessions.add(research_session)
    finally:
        database.dispose()
    typer.echo(str(research_session.id))


@cli.command("observe")
def observe(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
    path: Annotated[str, typer.Option(help="Absolute target path.")],
    method: Annotated[HttpMethod, typer.Option()] = HttpMethod.GET,
    identity: Annotated[str, typer.Option(help="anonymous, alice, bob, or admin.")] = "anonymous",
    follow_redirects: Annotated[bool, typer.Option(help="Follow HTTP redirects.")] = False,
) -> None:
    """Execute and persist one scoped observation through the Rust executor."""
    resolver = LaboratoryIdentityResolver()
    try:
        resolved_identity = resolver.resolve(identity)
    except ValueError as error:
        raise typer.BadParameter("identity must be anonymous, alice, bob, or admin") from error
    settings = get_settings()
    database = Database(settings.database_url)
    database.create_schema()
    executor = RustExecutorClient(
        settings.executor_path,
        process_grace_seconds=settings.executor_process_grace_seconds,
    )
    pipeline = ObservationPipeline(database, executor)
    try:
        result = asyncio.run(
            pipeline.observe(
                research_session_id=session_id,
                path=path,
                method=method,
                headers=resolved_identity.headers,
                follow_redirects=follow_redirects,
                identity_name=identity,
                identity_roles=list(resolved_identity.roles),
            )
        )
    finally:
        database.dispose()
    typer.echo(
        json.dumps(
            {
                "observation_id": str(result.observation.id),
                "evidence_id": str(result.evidence.id),
                "request_id": result.evidence.request_id,
                "status_code": result.evidence.response.status_code,
                "sha256": result.evidence.integrity_hash,
            },
            sort_keys=True,
        )
    )


@evidence_cli.command("show")
def evidence_show(evidence_id: UUID) -> None:
    """Display evidence with sensitive HTTP headers redacted."""
    settings = get_settings()
    database = Database(settings.database_url)
    try:
        with database.session_factory() as session:
            evidence = RepositorySet(session).evidence.get(evidence_id)
        if evidence is None:
            raise typer.BadParameter("evidence does not exist")
        output = evidence.model_dump(mode="json")
        output["request"]["headers"] = redact_headers(output["request"]["headers"])
        output["response"]["headers"] = redact_headers(output["response"]["headers"])
        typer.echo(json.dumps(output, sort_keys=True))
    finally:
        database.dispose()


@observations_cli.command("list")
def observations_list(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    """List normalized observations without assigning severity."""
    settings = get_settings()
    database = Database(settings.database_url)
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            observations = repositories.observations.list_by_session(session_id)
            rows = []
            for observation in observations:
                evidence = (
                    repositories.evidence.get(observation.evidence_id)
                    if observation.evidence_id is not None
                    else None
                )
                if evidence is not None:
                    rows.append(
                        {
                            "observation_id": str(observation.id),
                            "source": observation.source.value,
                            "request_id": observation.request_id,
                            "method": evidence.request.method,
                            "path": urlsplit(evidence.request.url).path,
                            "status": evidence.response.status_code,
                            "evidence_id": str(evidence.id),
                            "timestamp": observation.timestamp.isoformat(),
                        }
                    )
                elif observation.tool_artifact_id is not None:
                    rows.append(
                        {
                            "observation_id": str(observation.id),
                            "source": observation.source.value,
                            "source_type": observation.normalized_data.get("source_type"),
                            "tool_artifact_id": str(observation.tool_artifact_id),
                            "normalized_data": observation.normalized_data,
                            "trust": observation.trust.value,
                            "timestamp": observation.timestamp.isoformat(),
                        }
                    )
        typer.echo(json.dumps(rows, sort_keys=True))
    finally:
        database.dispose()


@hypotheses_cli.command("generate")
def hypotheses_generate(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
    fake_response: Annotated[
        Path | None,
        typer.Option(
            "--fake-response",
            help="Explicit HypothesisBatch JSON used only with AEGIS_LLM_PROVIDER=fake.",
        ),
    ] = None,
) -> None:
    """Generate, validate, and persist hypotheses without executing actions."""
    settings = get_settings()
    if fake_response is not None and settings.llm_provider != "fake":
        raise typer.BadParameter("--fake-response is only valid for the fake provider")
    configured_fake = None
    if fake_response is not None:
        try:
            configured_fake = HypothesisBatch.model_validate_json(
                fake_response.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            raise typer.BadParameter("fake response is not a valid HypothesisBatch JSON") from error
    database = Database(settings.database_url)
    database.create_schema()
    provider = create_llm_provider(settings, fake_response=configured_fake)
    context_builder = HypothesisContextBuilder(
        database,
        max_observations=settings.llm_context_max_observations,
        max_body_characters=settings.llm_context_max_body_characters,
        max_total_characters=settings.llm_context_max_total_characters,
    )
    engine = HypothesisEngine(
        database,
        provider,
        context_builder=context_builder,
        max_hypotheses=settings.max_hypotheses_per_run,
    )
    try:
        try:
            result = asyncio.run(engine.generate(session_id))
        except LLMProviderError as error:
            typer.echo(
                json.dumps(
                    {
                        "ok": False,
                        "error": {"code": error.code.value, "message": str(error)},
                    },
                    sort_keys=True,
                )
            )
            raise typer.Exit(code=1) from error
    finally:
        database.dispose()
    typer.echo(
        json.dumps(
            {
                "llm_run_id": str(result.llm_run.id),
                "provider": result.llm_run.provider,
                "model": result.llm_run.model,
                "prompt_version": result.llm_run.prompt_version,
                "generated": result.llm_run.generated_count,
                "accepted": result.llm_run.accepted_count,
                "rejected": result.llm_run.rejected_count,
            },
            sort_keys=True,
        )
    )


@hypotheses_cli.command("list")
def hypotheses_list(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    """List hypotheses as unverified model inferences."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            hypotheses = RepositorySet(session).hypotheses.list_by_session(session_id)
        rows = [
            {
                "id": str(item.id),
                "status": item.status.value,
                "confidence": item.confidence,
                "title": item.title,
                "observation_count": len(item.observation_ids),
                "created": item.provenance.collected_at.isoformat(),
            }
            for item in hypotheses
        ]
        typer.echo(json.dumps(rows, sort_keys=True))
    finally:
        database.dispose()


@hypotheses_cli.command("show")
def hypotheses_show(hypothesis_id: UUID) -> None:
    """Show one hypothesis and its provenance without any credential material."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            hypothesis = repositories.hypotheses.get(hypothesis_id)
            if hypothesis is None:
                raise typer.BadParameter("hypothesis does not exist")
            llm_run = (
                repositories.llm_runs.get(hypothesis.llm_run_id) if hypothesis.llm_run_id else None
            )
        output = hypothesis.model_dump(mode="json")
        output["llm_metadata"] = (
            {
                "run_id": str(llm_run.id),
                "provider": llm_run.provider,
                "model": llm_run.model,
                "prompt_version": llm_run.prompt_version,
                "context_sha256": llm_run.context_sha256,
            }
            if llm_run
            else None
        )
        typer.echo(json.dumps(output, sort_keys=True))
    finally:
        database.dispose()


def _experiment_runner(database: Database) -> ExperimentRunner:
    settings = get_settings()
    executor = RustExecutorClient(
        settings.executor_path,
        process_grace_seconds=settings.executor_process_grace_seconds,
    )
    return ExperimentRunner(
        database,
        RustPolicyClient(settings.policy_path, settings.policy_process_timeout_seconds),
        ObservationPipeline(database, executor),
        settings,
    )


@experiments_cli.command("generate")
def experiments_generate(
    hypothesis_id: Annotated[UUID, typer.Option("--hypothesis")],
    fake_response: Annotated[Path | None, typer.Option("--fake-response")] = None,
) -> None:
    """Generate and validate an experiment proposal; never execute it."""
    settings = get_settings()
    if fake_response is not None and settings.llm_provider != "fake":
        raise typer.BadParameter("--fake-response is only valid for the fake provider")
    configured = None
    if fake_response:
        try:
            configured = ExperimentProposal.model_validate_json(fake_response.read_text())
        except (OSError, ValueError) as error:
            raise typer.BadParameter("fake response is not a valid ExperimentProposal") from error
    database = Database(settings.database_url)
    database.create_schema()
    try:
        try:
            result = asyncio.run(
                ExperimentEngine(
                    database, create_llm_provider(settings, fake_response=configured)
                ).generate(hypothesis_id)
            )
        except LLMProviderError as error:
            typer.echo(
                json.dumps(
                    {"ok": False, "error": {"code": error.code.value, "message": str(error)}},
                    sort_keys=True,
                )
            )
            raise typer.Exit(code=1) from error
        typer.echo(
            json.dumps(
                {
                    "llm_run_id": str(result.llm_run.id),
                    "experiment_id": str(result.experiment.id),
                    "status": result.experiment.status.value,
                    "candidate": result.experiment.candidate.model_dump(mode="json"),
                    "control": result.experiment.control.model_dump(mode="json"),
                    "risk": result.experiment.risk.value,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@experiments_cli.command("show")
def experiments_show(experiment_id: UUID) -> None:
    """Show a logical experiment, policy audit, and evidence lineage without credentials."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            experiment = repositories.experiments.get(experiment_id)
            if experiment is None:
                raise typer.BadParameter("experiment does not exist")
            decisions = repositories.policy_decisions.list_by_experiment(experiment_id)
            executions = repositories.experiment_executions.list_by_experiment(experiment_id)
        typer.echo(
            json.dumps(
                {
                    "experiment": experiment.model_dump(mode="json"),
                    "policy_decisions": [item.model_dump(mode="json") for item in decisions],
                    "executions": [item.model_dump(mode="json") for item in executions],
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@experiments_cli.command("check")
def experiments_check(experiment_id: UUID) -> None:
    """Persist a candidate/control policy decision without executing HTTP."""
    database = Database(get_settings().database_url)
    try:
        result = asyncio.run(_experiment_runner(database).check(experiment_id))
        typer.echo(
            json.dumps(
                {
                    "candidate": result.candidate.model_dump(mode="json"),
                    "control": result.control.model_dump(mode="json"),
                    "allowed": result.allowed,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@experiments_cli.command("run")
def experiments_run(experiment_id: UUID) -> None:
    """Explicitly policy-check then execute control followed by candidate."""
    database = Database(get_settings().database_url)
    try:
        result = asyncio.run(_experiment_runner(database).run(experiment_id))
        typer.echo(json.dumps(result.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


def _verification_engine(database: Database) -> VerificationEngine:
    return VerificationEngine(
        database,
        min_verification_runs=get_settings().min_verification_runs,
    )


@verify_cli.command("execution")
def verify_execution(execution_id: UUID) -> None:
    """Verify one completed execution and persist its comparisons and verdict."""
    database = Database(get_settings().database_url)
    database.create_schema()
    try:
        result = _verification_engine(database).verify_execution(execution_id)
        typer.echo(
            json.dumps(
                {
                    "verification": result.verification.model_dump(mode="json"),
                    "finding_id": str(result.finding.id) if result.finding else None,
                },
                sort_keys=True,
            )
        )
    finally:
        database.dispose()


@verify_cli.command("experiment")
def verify_experiment(experiment_id: UUID) -> None:
    """Verify unverified executions and calculate the deterministic aggregate."""
    database = Database(get_settings().database_url)
    database.create_schema()
    try:
        result = _verification_engine(database).verify_experiment(experiment_id)
        typer.echo(json.dumps(result.model_dump(mode="json"), sort_keys=True))
    finally:
        database.dispose()


@findings_cli.command("list")
def findings_list(
    session_id: Annotated[UUID, typer.Option("--session", help="Research session UUID.")],
) -> None:
    """List persisted findings, including disputed aggregate states."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            findings = RepositorySet(session).findings.list_by_session(session_id)
        rows = [
            {
                "id": str(item.id),
                "status": item.verification_status.value,
                "title": item.title,
                "hypothesis_id": str(item.hypothesis_id),
                "experiment_id": str(item.experiment_id) if item.experiment_id else None,
                "evidence_count": len(item.evidence_ids) + len(item.control_evidence_ids),
                "created": item.created_at.isoformat(),
            }
            for item in findings
        ]
        typer.echo(json.dumps(rows, sort_keys=True))
    finally:
        database.dispose()


@findings_cli.command("show")
def findings_show(finding_id: UUID) -> None:
    """Show finding lineage and deterministic comparisons without credentials."""
    database = Database(get_settings().database_url)
    try:
        with database.session_factory() as session:
            repositories = RepositorySet(session)
            finding = repositories.findings.get(finding_id)
            if finding is None:
                raise typer.BadParameter("finding does not exist")
            verifications = [
                item
                for verification_id in finding.verification_result_ids
                if (item := repositories.verification_results.get(verification_id)) is not None
            ]
        output = finding.model_dump(mode="json")
        output["verifications"] = [item.model_dump(mode="json") for item in verifications]
        typer.echo(json.dumps(output, sort_keys=True))
    finally:
        database.dispose()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
