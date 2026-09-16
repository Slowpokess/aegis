"""Phase 12 typed acquisition and closed-loop controller persistence.

Revision ID: 0012_closed_loop_controller
Revises: 0011_research_strategy
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_closed_loop_controller"
down_revision: str | None = "0011_research_strategy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _indexes(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column])


def upgrade() -> None:
    op.create_table(
        "research_budgets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("controller_status", sa.String(30), nullable=False),
        sa.Column("updated_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.UniqueConstraint("research_session_id"),
    )
    _indexes("research_budgets", ("research_session_id", "controller_status", "updated_at"))
    op.create_table(
        "controller_steps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.UniqueConstraint("research_session_id", "step_number"),
    )
    _indexes(
        "controller_steps",
        ("research_session_id", "step_number", "context_hash", "status", "created_at"),
    )
    op.create_table(
        "research_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("controller_step_id", sa.String(36), nullable=False),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("semantic_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["controller_step_id"], ["controller_steps.id"]),
    )
    _indexes(
        "research_actions",
        (
            "research_session_id",
            "controller_step_id",
            "action_type",
            "semantic_hash",
            "status",
            "created_at",
        ),
    )
    op.create_table(
        "research_action_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("action_id", sa.String(36), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("started_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["action_id"], ["research_actions.id"]),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.UniqueConstraint("action_id"),
    )
    _indexes(
        "research_action_results",
        ("action_id", "research_session_id", "status", "started_at"),
    )


def downgrade() -> None:
    op.drop_table("research_action_results")
    op.drop_table("research_actions")
    op.drop_table("controller_steps")
    op.drop_table("research_budgets")
