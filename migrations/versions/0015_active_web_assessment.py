"""Phase 15.3 active web candidate multi-source provenance.

Revision ID: 0015_active_web_assessment
Revises: 0014_web_surface
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_active_web_assessment"
down_revision: str | None = "0014_web_surface"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "web_candidate_provenance",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("web_template_candidate_id", sa.String(36), nullable=False),
        sa.Column("web_resource_id", sa.String(36), nullable=False),
        sa.Column("tool_artifact_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("tool_run_id", sa.String(36), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(
            ["web_template_candidate_id"], ["web_template_candidates.id"]
        ),
        sa.ForeignKeyConstraint(["web_resource_id"], ["web_resources.id"]),
        sa.ForeignKeyConstraint(["tool_artifact_id"], ["tool_artifacts.id"]),
        sa.ForeignKeyConstraint(["observation_id"], ["observations.id"]),
        sa.ForeignKeyConstraint(["tool_run_id"], ["tool_runs.id"]),
        sa.UniqueConstraint("web_template_candidate_id", "observation_id", "source"),
    )
    for column in (
        "research_session_id",
        "web_template_candidate_id",
        "web_resource_id",
        "tool_artifact_id",
        "observation_id",
        "tool_run_id",
        "source",
        "created_at",
    ):
        op.create_index(
            f"ix_web_candidate_provenance_{column}",
            "web_candidate_provenance",
            [column],
        )


def downgrade() -> None:
    op.drop_table("web_candidate_provenance")
