"""Add Phase 6 benchmark and scenario evaluation persistence.

Revision ID: 0006_phase6
Revises: 0005_phase5
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0006_phase6"
down_revision: str | None = "0005_phase5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "benchmark_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("mode", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("started_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("mode", "status", "provider", "model", "started_at"):
        op.create_index(f"ix_benchmark_runs_{column}", "benchmark_runs", [column])
    op.create_table(
        "scenario_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("benchmark_run_id", sa.String(length=36), nullable=False),
        sa.Column("scenario_id", sa.String(length=20), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.ForeignKeyConstraint(["benchmark_run_id"], ["benchmark_runs.id"]),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("benchmark_run_id", "scenario_id"),
    )
    for column in ("benchmark_run_id", "scenario_id", "research_session_id", "status"):
        op.create_index(f"ix_scenario_runs_{column}", "scenario_runs", [column])
    op.create_table(
        "scenario_evaluations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("benchmark_run_id", sa.String(length=36), nullable=False),
        sa.Column("scenario_run_id", sa.String(length=36), nullable=False),
        sa.Column("scenario_id", sa.String(length=20), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("classification", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["benchmark_run_id"], ["benchmark_runs.id"]),
        sa.ForeignKeyConstraint(["scenario_run_id"], ["scenario_runs.id"]),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("benchmark_run_id", "scenario_id"),
    )
    for column in (
        "benchmark_run_id",
        "scenario_run_id",
        "scenario_id",
        "research_session_id",
        "classification",
    ):
        op.create_index(
            f"ix_scenario_evaluations_{column}", "scenario_evaluations", [column]
        )


def downgrade() -> None:
    op.drop_table("scenario_evaluations")
    op.drop_table("scenario_runs")
    op.drop_table("benchmark_runs")
