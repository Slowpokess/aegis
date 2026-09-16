"""Add Phase 3 LLM runs and hypothesis lineage.

Revision ID: 0003_phase3
Revises: 0002_phase2
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0003_phase3"
down_revision: str | None = "0002_phase2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "llm_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("prompt_version", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_llm_runs_research_session_id", "llm_runs", ["research_session_id"])
    op.create_index("ix_llm_runs_provider", "llm_runs", ["provider"])
    op.create_index("ix_llm_runs_model", "llm_runs", ["model"])
    op.create_index("ix_llm_runs_prompt_version", "llm_runs", ["prompt_version"])
    op.create_index("ix_llm_runs_status", "llm_runs", ["status"])

    with op.batch_alter_table("hypotheses") as batch:
        batch.add_column(sa.Column("research_session_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("llm_run_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_hypotheses_research_session_id",
            "research_sessions",
            ["research_session_id"],
            ["id"],
        )
        batch.create_foreign_key(
            "fk_hypotheses_llm_run_id", "llm_runs", ["llm_run_id"], ["id"]
        )
        batch.create_index("ix_hypotheses_research_session_id", ["research_session_id"])
        batch.create_index("ix_hypotheses_llm_run_id", ["llm_run_id"])


def downgrade() -> None:
    with op.batch_alter_table("hypotheses") as batch:
        batch.drop_index("ix_hypotheses_llm_run_id")
        batch.drop_index("ix_hypotheses_research_session_id")
        batch.drop_constraint("fk_hypotheses_llm_run_id", type_="foreignkey")
        batch.drop_constraint("fk_hypotheses_research_session_id", type_="foreignkey")
        batch.drop_column("llm_run_id")
        batch.drop_column("research_session_id")

    op.drop_table("llm_runs")
