"""Phase 16.2 persistent client verification lifecycle.

Revision ID: 0016_client_verification_runs
Revises: 0015_active_web_assessment
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_client_verification_runs"
down_revision: str | None = "0015_active_web_assessment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "client_verification_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("research_action_id", sa.String(36), nullable=False),
        sa.Column("action_approval_id", sa.String(36), nullable=False),
        sa.Column("web_resource_id", sa.String(36), nullable=False),
        sa.Column("hypothesis_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["research_action_id"], ["research_actions.id"]),
        sa.ForeignKeyConstraint(["action_approval_id"], ["action_approvals.id"]),
        sa.ForeignKeyConstraint(["web_resource_id"], ["web_resources.id"]),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"]),
    )
    for column in (
        "research_session_id",
        "research_action_id",
        "action_approval_id",
        "web_resource_id",
        "hypothesis_id",
        "status",
        "created_at",
    ):
        op.create_index(
            f"ix_client_verification_runs_{column}",
            "client_verification_runs",
            [column],
        )


def downgrade() -> None:
    op.drop_table("client_verification_runs")
