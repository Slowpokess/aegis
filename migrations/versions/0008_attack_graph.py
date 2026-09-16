"""Add Phase 8 attack graph snapshots and candidate signals.

Revision ID: 0008_phase8
Revises: 0007_phase7
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0008_phase8"
down_revision: str | None = "0007_phase7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_graph_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("system_model_build_id", sa.String(length=36), nullable=True),
        sa.Column("graph_hash", sa.String(length=64), nullable=False),
        sa.Column("system_model_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["system_model_build_id"], ["system_model_builds.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "research_session_id",
        "system_model_build_id",
        "graph_hash",
        "system_model_hash",
        "status",
        "created_at",
    ):
        op.create_index(
            f"ix_attack_graph_snapshots_{column}", "attack_graph_snapshots", [column]
        )
    op.create_table(
        "candidate_signals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("graph_id", sa.String(length=36), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("signal_type", sa.String(length=60), nullable=False),
        sa.Column("semantic_key", sa.String(length=2048), nullable=False),
        sa.Column("subject_entity_id", sa.String(length=36), nullable=False),
        sa.Column("target_entity_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["graph_id"], ["attack_graph_snapshots.id"]),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("graph_id", "semantic_key"),
    )
    for column in (
        "graph_id",
        "research_session_id",
        "signal_type",
        "semantic_key",
        "subject_entity_id",
        "target_entity_id",
    ):
        op.create_index(f"ix_candidate_signals_{column}", "candidate_signals", [column])


def downgrade() -> None:
    op.drop_table("candidate_signals")
    op.drop_table("attack_graph_snapshots")
