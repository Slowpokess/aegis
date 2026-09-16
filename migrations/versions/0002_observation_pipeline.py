"""Add research sessions and Phase 2 evidence lineage.

Revision ID: 0002_phase2
Revises: 0001_phase0
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0002_phase2"
down_revision: str | None = "0001_phase0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "research_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_research_sessions_asset_id", "research_sessions", ["asset_id"])
    op.create_index("ix_research_sessions_status", "research_sessions", ["status"])

    with op.batch_alter_table("evidence") as batch:
        batch.alter_column("experiment_id", existing_type=sa.String(length=36), nullable=True)
        batch.add_column(sa.Column("research_session_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("request_id", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("executor", sa.String(length=100), nullable=True))
        batch.create_foreign_key(
            "fk_evidence_research_session_id",
            "research_sessions",
            ["research_session_id"],
            ["id"],
        )
        batch.create_unique_constraint(
            "uq_evidence_session_request", ["research_session_id", "request_id"]
        )
        batch.create_index("ix_evidence_research_session_id", ["research_session_id"])
        batch.create_index("ix_evidence_request_id", ["request_id"])
        batch.create_index("ix_evidence_executor", ["executor"])

    with op.batch_alter_table("observations") as batch:
        batch.add_column(sa.Column("research_session_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("evidence_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("request_id", sa.String(length=128), nullable=True))
        batch.create_foreign_key(
            "fk_observations_research_session_id",
            "research_sessions",
            ["research_session_id"],
            ["id"],
        )
        batch.create_foreign_key("fk_observations_evidence_id", "evidence", ["evidence_id"], ["id"])
        batch.create_index("ix_observations_research_session_id", ["research_session_id"])
        batch.create_index("ix_observations_evidence_id", ["evidence_id"])
        batch.create_index("ix_observations_request_id", ["request_id"])


def downgrade() -> None:
    with op.batch_alter_table("observations") as batch:
        batch.drop_index("ix_observations_request_id")
        batch.drop_index("ix_observations_evidence_id")
        batch.drop_index("ix_observations_research_session_id")
        batch.drop_constraint("fk_observations_evidence_id", type_="foreignkey")
        batch.drop_constraint("fk_observations_research_session_id", type_="foreignkey")
        batch.drop_column("request_id")
        batch.drop_column("evidence_id")
        batch.drop_column("research_session_id")

    with op.batch_alter_table("evidence") as batch:
        batch.drop_index("ix_evidence_executor")
        batch.drop_index("ix_evidence_request_id")
        batch.drop_index("ix_evidence_research_session_id")
        batch.drop_constraint("uq_evidence_session_request", type_="unique")
        batch.drop_constraint("fk_evidence_research_session_id", type_="foreignkey")
        batch.drop_column("executor")
        batch.drop_column("request_id")
        batch.drop_column("research_session_id")
        batch.alter_column("experiment_id", existing_type=sa.String(length=36), nullable=False)

    op.drop_table("research_sessions")
