"""Phase 13 operator control plane and reporting persistence.

Revision ID: 0013_operator_reporting
Revises: 0012_closed_loop_controller
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_operator_reporting"
down_revision: str | None = "0012_closed_loop_controller"
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
        "research_policies",
        sa.Column("profile", sa.String(30), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    _indexes("research_policies", ("profile", "created_at"))
    _payload_table(
        "research_projects",
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("research_policy_id", sa.String(36), nullable=False),
        sa.Column("updated_at", sa.String(64), nullable=False),
        constraints=(sa.ForeignKeyConstraint(["research_policy_id"], ["research_policies.id"]),),
    )
    _indexes("research_projects", ("status", "research_policy_id", "updated_at"))
    with op.batch_alter_table("research_sessions") as batch:
        batch.add_column(sa.Column("project_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("project_scope_revision", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_research_sessions_project",
            "research_projects",
            ["project_id"],
            ["id"],
        )
    _indexes("research_sessions", ("project_id",))
    _payload_table(
        "action_approvals",
        sa.Column("project_id", sa.String(36), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["project_id"], ["research_projects.id"]),
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.ForeignKeyConstraint(["action_id"], ["research_actions.id"]),
            sa.UniqueConstraint("action_id"),
        ),
    )
    _indexes(
        "action_approvals",
        ("project_id", "research_session_id", "action_id", "status", "created_at"),
    )
    _payload_table(
        "research_events",
        sa.Column("project_id", sa.String(36), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=True),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("idempotency_key", sa.String(500), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["project_id"], ["research_projects.id"]),
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
            sa.UniqueConstraint("idempotency_key"),
        ),
    )
    _indexes(
        "research_events",
        (
            "project_id",
            "research_session_id",
            "sequence_number",
            "event_type",
            "severity",
            "idempotency_key",
            "created_at",
        ),
    )
    _payload_table(
        "report_metadata",
        sa.Column("project_id", sa.String(36), nullable=False),
        sa.Column("research_session_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("generated_at", sa.String(64), nullable=False),
        constraints=(
            sa.ForeignKeyConstraint(["project_id"], ["research_projects.id"]),
            sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        ),
    )
    _indexes(
        "report_metadata",
        ("project_id", "research_session_id", "status", "generated_at"),
    )


def downgrade() -> None:
    op.drop_table("report_metadata")
    op.drop_table("research_events")
    op.drop_table("action_approvals")
    op.drop_index("ix_research_sessions_project_id", table_name="research_sessions")
    with op.batch_alter_table("research_sessions") as batch:
        batch.drop_constraint("fk_research_sessions_project", type_="foreignkey")
        batch.drop_column("project_scope_revision")
        batch.drop_column("project_id")
    op.drop_table("research_projects")
    op.drop_table("research_policies")
