"""Evidence-bound verification recommendations.

Revision ID: 0017_verification_recommendations
Revises: 0016_client_verification_runs
"""
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

revision: str = "0017_verification_recommendations"
down_revision: str | None = "0016_client_verification_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

def upgrade() -> None:
    op.create_table("verification_recommendations",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False), sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("verdict", sa.String(40), nullable=False), sa.Column("recommended_action", sa.String(40), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["client_verification_runs.id"]),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.UniqueConstraint("run_id"),
    )
    for column in ("run_id", "research_session_id", "verdict", "recommended_action", "created_at"):
        op.create_index(f"ix_verification_recommendations_{column}", "verification_recommendations", [column])

def downgrade() -> None:
    op.drop_table("verification_recommendations")
