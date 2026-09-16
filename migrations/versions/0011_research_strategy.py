"""Phase 11 research strategy persistence.

Revision ID: 0011_research_strategy
Revises: 0010_research_planner
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_research_strategy"
down_revision: str | None = "0010_research_planner"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _indexes(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column])


def upgrade() -> None:
    op.create_table(
        "knowledge_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("system_model_hash", sa.String(64), nullable=False),
        sa.Column("graph_hash", sa.String(64), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
    )
    _indexes(
        "knowledge_snapshots",
        ("research_session_id", "system_model_hash", "graph_hash", "sha256", "created_at"),
    )
    op.create_table(
        "evidence_gaps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("semantic_key", sa.String(2048), nullable=False),
        sa.Column("gap_type", sa.String(80), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.UniqueConstraint("research_session_id", "semantic_key"),
    )
    _indexes(
        "evidence_gaps",
        ("research_session_id", "semantic_key", "gap_type", "status", "created_at"),
    )
    op.create_table(
        "research_questions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("gap_id", sa.String(36), nullable=False),
        sa.Column("semantic_key", sa.String(2048), nullable=False),
        sa.Column("question_type", sa.String(80), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["gap_id"], ["evidence_gaps.id"]),
        sa.UniqueConstraint("research_session_id", "semantic_key"),
    )
    _indexes(
        "research_questions",
        ("research_session_id", "gap_id", "semantic_key", "question_type", "status"),
    )
    op.create_table(
        "strategy_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("knowledge_snapshot_id", sa.String(36), nullable=False),
        sa.Column("mode", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("started_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["knowledge_snapshot_id"], ["knowledge_snapshots.id"]),
    )
    _indexes(
        "strategy_runs",
        ("research_session_id", "knowledge_snapshot_id", "mode", "status", "started_at"),
    )


def downgrade() -> None:
    op.drop_table("strategy_runs")
    op.drop_table("research_questions")
    op.drop_table("evidence_gaps")
    op.drop_table("knowledge_snapshots")
