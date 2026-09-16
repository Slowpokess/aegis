"""Add Phase 9 controlled discovery persistence.

Revision ID: 0009_phase9
Revises: 0008_phase8
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0009_phase9"
down_revision: str | None = "0008_phase8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _indexes(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column])


def upgrade() -> None:
    op.create_table(
        "discovery_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("profile", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("discovery_plans", ("research_session_id", "profile", "status", "created_at"))
    op.create_table(
        "tool_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("discovery_plan_id", sa.String(length=36), nullable=False),
        sa.Column("tool_id", sa.String(length=50), nullable=False),
        sa.Column("profile", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("started_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["discovery_plan_id"], ["discovery_plans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "tool_runs",
        ("research_session_id", "discovery_plan_id", "tool_id", "profile", "status", "started_at"),
    )
    op.create_table(
        "tool_policy_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("discovery_plan_id", sa.String(length=36), nullable=False),
        sa.Column("tool_run_id", sa.String(length=36), nullable=False),
        sa.Column("allowed", sa.String(length=5), nullable=False),
        sa.Column("reason", sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["discovery_plan_id"], ["discovery_plans.id"]),
        sa.ForeignKeyConstraint(["tool_run_id"], ["tool_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "tool_policy_decisions",
        ("research_session_id", "discovery_plan_id", "tool_run_id", "allowed", "reason"),
    )
    op.create_table(
        "tool_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("tool_run_id", sa.String(length=36), nullable=False),
        sa.Column("tool_id", sa.String(length=50), nullable=False),
        sa.Column("artifact_type", sa.String(length=50), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["tool_run_id"], ["tool_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "tool_artifacts",
        ("research_session_id", "tool_run_id", "tool_id", "artifact_type", "sha256", "created_at"),
    )
    with op.batch_alter_table("observations") as batch:
        batch.add_column(sa.Column("tool_artifact_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_observations_tool_artifact", "tool_artifacts", ["tool_artifact_id"], ["id"]
        )
        batch.create_index("ix_observations_tool_artifact_id", ["tool_artifact_id"])


def downgrade() -> None:
    with op.batch_alter_table("observations") as batch:
        batch.drop_index("ix_observations_tool_artifact_id")
        batch.drop_constraint("fk_observations_tool_artifact", type_="foreignkey")
        batch.drop_column("tool_artifact_id")
    op.drop_table("tool_artifacts")
    op.drop_table("tool_policy_decisions")
    op.drop_table("tool_runs")
    op.drop_table("discovery_plans")
