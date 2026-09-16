"""Phase 10 research planner persistence.

Revision ID: 0010_research_planner
Revises: 0009_phase9
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_research_planner"
down_revision: str | None = "0009_phase9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "research_steps",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("context_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("started_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.UniqueConstraint("research_session_id", "step_number"),
    )
    for column in ("research_session_id", "step_number", "context_hash", "status", "started_at"):
        op.create_index(f"ix_research_steps_{column}", "research_steps", [column])
    op.create_table(
        "research_intents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("research_step_id", sa.String(length=36), nullable=False),
        sa.Column("intent_type", sa.String(length=60), nullable=False),
        sa.Column("semantic_key", sa.String(length=2048), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["research_step_id"], ["research_steps.id"]),
    )
    for column in (
        "research_session_id",
        "research_step_id",
        "intent_type",
        "semantic_key",
        "status",
        "created_at",
    ):
        op.create_index(f"ix_research_intents_{column}", "research_intents", [column])


def downgrade() -> None:
    op.drop_table("research_intents")
    op.drop_table("research_steps")
