"""Add Phase 4 experiment execution and policy audit lineage.

Revision ID: 0004_phase4
Revises: 0003_phase3
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0004_phase4"
down_revision: str | None = "0003_phase3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("llm_runs") as batch:
        batch.add_column(
            sa.Column(
                "purpose",
                sa.String(length=40),
                nullable=False,
                server_default="HYPOTHESIS_GENERATION",
            )
        )
        batch.create_index("ix_llm_runs_purpose", ["purpose"])

    with op.batch_alter_table("experiments") as batch:
        batch.add_column(sa.Column("research_session_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("llm_run_id", sa.String(length=36), nullable=True))
        batch.add_column(
            sa.Column("status", sa.String(length=30), nullable=False, server_default="DRAFT")
        )
        batch.create_foreign_key(
            "fk_experiments_research_session_id",
            "research_sessions",
            ["research_session_id"],
            ["id"],
        )
        batch.create_foreign_key("fk_experiments_llm_run_id", "llm_runs", ["llm_run_id"], ["id"])
        batch.create_index("ix_experiments_research_session_id", ["research_session_id"])
        batch.create_index("ix_experiments_llm_run_id", ["llm_run_id"])
        batch.create_index("ix_experiments_status", ["status"])

    op.create_table(
        "experiment_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("experiment_id", sa.String(length=36), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("started_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"]),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("experiment_id", "research_session_id", "status", "started_at"):
        op.create_index(f"ix_experiment_executions_{column}", "experiment_executions", [column])

    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("decision_id", sa.String(length=128), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("experiment_id", sa.String(length=36), nullable=False),
        sa.Column("experiment_execution_id", sa.String(length=36), nullable=True),
        sa.Column("action_role", sa.String(length=20), nullable=False),
        sa.Column("allowed", sa.String(length=5), nullable=False),
        sa.Column("reason_code", sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"]),
        sa.ForeignKeyConstraint(["experiment_execution_id"], ["experiment_executions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("decision_id"),
    )
    for column in (
        "decision_id",
        "research_session_id",
        "experiment_id",
        "experiment_execution_id",
        "action_role",
        "allowed",
        "reason_code",
    ):
        op.create_index(f"ix_policy_decisions_{column}", "policy_decisions", [column])

    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("experiment_role", sa.String(length=20), nullable=True))
        batch.create_index("ix_evidence_experiment_role", ["experiment_role"])


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch:
        batch.drop_index("ix_evidence_experiment_role")
        batch.drop_column("experiment_role")
    op.drop_table("policy_decisions")
    op.drop_table("experiment_executions")
    with op.batch_alter_table("experiments") as batch:
        batch.drop_index("ix_experiments_status")
        batch.drop_index("ix_experiments_llm_run_id")
        batch.drop_index("ix_experiments_research_session_id")
        batch.drop_constraint("fk_experiments_llm_run_id", type_="foreignkey")
        batch.drop_constraint("fk_experiments_research_session_id", type_="foreignkey")
        batch.drop_column("status")
        batch.drop_column("llm_run_id")
        batch.drop_column("research_session_id")
    with op.batch_alter_table("llm_runs") as batch:
        batch.drop_index("ix_llm_runs_purpose")
        batch.drop_column("purpose")
