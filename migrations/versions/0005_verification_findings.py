"""Add Phase 5 verification results and finding lineage.

Revision ID: 0005_phase5
Revises: 0004_phase4
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0005_phase5"
down_revision: str | None = "0004_phase4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "verification_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("experiment_id", sa.String(length=36), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("verifier_version", sa.String(length=50), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("rule_version", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"]),
        sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"]),
        sa.ForeignKeyConstraint(["execution_id"], ["experiment_executions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "research_session_id",
        "hypothesis_id",
        "experiment_id",
        "execution_id",
        "verdict",
        "verifier_version",
        "rule_id",
        "rule_version",
        "created_at",
    ):
        op.create_index(f"ix_verification_results_{column}", "verification_results", [column])

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("research_session_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("experiment_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_findings_research_session_id",
            "research_sessions",
            ["research_session_id"],
            ["id"],
        )
        batch.create_foreign_key(
            "fk_findings_experiment_id", "experiments", ["experiment_id"], ["id"]
        )
        batch.create_index("ix_findings_research_session_id", ["research_session_id"])
        batch.create_index("ix_findings_experiment_id", ["experiment_id"])


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_experiment_id")
        batch.drop_index("ix_findings_research_session_id")
        batch.drop_constraint("fk_findings_experiment_id", type_="foreignkey")
        batch.drop_constraint("fk_findings_research_session_id", type_="foreignkey")
        batch.drop_column("experiment_id")
        batch.drop_column("research_session_id")
    op.drop_table("verification_results")
