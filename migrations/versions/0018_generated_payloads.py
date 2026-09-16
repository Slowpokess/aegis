"""Persist sealed inert payload generation metadata.

Revision ID: 0018_generated_payloads
Revises: 0017_verification_recommendations
"""
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

revision: str = "0018_generated_payloads"
down_revision: str | None = "0017_verification_recommendations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

def upgrade() -> None:
    op.create_table("generated_payloads", sa.Column("id", sa.String(36), primary_key=True), sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("verification_run_id", sa.String(36), nullable=False), sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("vulnerability_class", sa.String(40), nullable=False), sa.Column("injection_context", sa.String(40), nullable=False), sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["verification_run_id"], ["client_verification_runs.id"]), sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]), sa.UniqueConstraint("verification_run_id"))
    for column in ("verification_run_id", "research_session_id", "vulnerability_class", "injection_context", "created_at"):
        op.create_index(f"ix_generated_payloads_{column}", "generated_payloads", [column])

def downgrade() -> None:
    op.drop_table("generated_payloads")
