"""Phase 15.2 persistent Web Surface projection.

Revision ID: 0014_web_surface
Revises: 0013_operator_reporting
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_web_surface"
down_revision: str | None = "0013_operator_reporting"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _indexes(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column])


def _payload_table(name: str, *columns: sa.Column[object], constraints=()) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        *columns,
        *constraints,
    )


def upgrade() -> None:
    _payload_table(
        "web_resources",
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("canonical_key", sa.String(4096), nullable=False),
        sa.Column("method", sa.String(20), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("resource_type", sa.String(30), nullable=False),
        sa.Column("system_endpoint_id", sa.String(36), nullable=True),
        constraints=(
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.ForeignKeyConstraint(["system_endpoint_id"], ["system_endpoints.id"]),
            sa.UniqueConstraint("research_session_id", "canonical_key"),
        ),
    )
    _indexes(
        "web_resources",
        (
            "research_session_id",
            "canonical_key",
            "method",
            "path",
            "resource_type",
            "system_endpoint_id",
        ),
    )
    _payload_table(
        "web_resource_provenance",
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("web_resource_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("tool_artifact_id", sa.String(36), nullable=True),
        sa.Column("evidence_id", sa.String(36), nullable=True),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("observed_at", sa.String(64), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.ForeignKeyConstraint(["web_resource_id"], ["web_resources.id"]),
            sa.ForeignKeyConstraint(["observation_id"], ["observations.id"]),
            sa.ForeignKeyConstraint(["tool_artifact_id"], ["tool_artifacts.id"]),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"]),
            sa.UniqueConstraint("web_resource_id", "observation_id", "source"),
        ),
    )
    _indexes(
        "web_resource_provenance",
        (
            "research_session_id",
            "web_resource_id",
            "observation_id",
            "tool_artifact_id",
            "evidence_id",
            "source",
            "observed_at",
        ),
    )
    _payload_table(
        "web_parameters",
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("web_resource_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("location", sa.String(30), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.ForeignKeyConstraint(["web_resource_id"], ["web_resources.id"]),
            sa.UniqueConstraint("web_resource_id", "name", "location"),
        ),
    )
    _indexes(
        "web_parameters", ("research_session_id", "web_resource_id", "name", "location")
    )
    _payload_table(
        "http_request_templates",
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("web_resource_id", sa.String(36), nullable=False),
        sa.Column("semantic_key", sa.String(64), nullable=False),
        sa.Column("method", sa.String(20), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.ForeignKeyConstraint(["web_resource_id"], ["web_resources.id"]),
            sa.UniqueConstraint("research_session_id", "semantic_key"),
        ),
    )
    _indexes(
        "http_request_templates",
        ("research_session_id", "web_resource_id", "semantic_key", "method"),
    )
    _payload_table(
        "web_template_candidates",
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("web_resource_id", sa.String(36), nullable=False),
        sa.Column("tool_artifact_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("semantic_key", sa.String(64), nullable=False),
        sa.Column("classification", sa.String(30), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.ForeignKeyConstraint(["web_resource_id"], ["web_resources.id"]),
            sa.ForeignKeyConstraint(["tool_artifact_id"], ["tool_artifacts.id"]),
            sa.ForeignKeyConstraint(["observation_id"], ["observations.id"]),
            sa.UniqueConstraint("research_session_id", "semantic_key"),
        ),
    )
    _indexes(
        "web_template_candidates",
        (
            "research_session_id",
            "web_resource_id",
            "tool_artifact_id",
            "observation_id",
            "semantic_key",
            "classification",
        ),
    )
    _payload_table(
        "web_surface_snapshots",
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("web_surface_version", sa.String(50), nullable=False),
        sa.Column("web_surface_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        ),
    )
    _indexes(
        "web_surface_snapshots",
        ("research_session_id", "web_surface_version", "web_surface_sha256", "created_at"),
    )


def downgrade() -> None:
    op.drop_table("web_surface_snapshots")
    op.drop_table("web_template_candidates")
    op.drop_table("http_request_templates")
    op.drop_table("web_parameters")
    op.drop_table("web_resource_provenance")
    op.drop_table("web_resources")
