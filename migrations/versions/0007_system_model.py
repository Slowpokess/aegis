"""Add Phase 7 persistent system model projection.

Revision ID: 0007_phase7
Revises: 0006_phase6
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0007_phase7"
down_revision: str | None = "0006_phase6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _fact_table(
    name: str,
    *columns: sa.Column,
    constraints: tuple[sa.Constraint, ...] = (),
) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("canonical_identifier", sa.String(length=2048), nullable=False),
        *columns,
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("research_session_id", "canonical_identifier"),
        *constraints,
    )
    op.create_index(f"ix_{name}_research_session_id", name, ["research_session_id"])
    op.create_index(f"ix_{name}_canonical_identifier", name, ["canonical_identifier"])


def upgrade() -> None:
    _fact_table(
        "system_assets",
        sa.Column("asset_type", sa.String(length=30), nullable=False),
        sa.Column("parent_asset_id", sa.String(length=36), nullable=True),
        constraints=(sa.ForeignKeyConstraint(["parent_asset_id"], ["system_assets.id"]),),
    )
    op.create_index("ix_system_assets_asset_type", "system_assets", ["asset_type"])
    op.create_index("ix_system_assets_parent_asset_id", "system_assets", ["parent_asset_id"])
    _fact_table(
        "system_services",
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        constraints=(sa.ForeignKeyConstraint(["asset_id"], ["system_assets.id"]),),
    )
    op.create_index("ix_system_services_asset_id", "system_services", ["asset_id"])
    _fact_table(
        "system_endpoints",
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column("method", sa.String(length=20), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        constraints=(sa.ForeignKeyConstraint(["service_id"], ["system_services.id"]),),
    )
    for column in ("service_id", "method", "path"):
        op.create_index(f"ix_system_endpoints_{column}", "system_endpoints", [column])
    _fact_table("system_roles")
    _fact_table(
        "system_identities",
        sa.Column("role_id", sa.String(length=36), nullable=True),
        constraints=(sa.ForeignKeyConstraint(["role_id"], ["system_roles.id"]),),
    )
    op.create_index("ix_system_identities_role_id", "system_identities", ["role_id"])
    _fact_table(
        "system_data_objects",
        sa.Column("data_type", sa.String(length=40), nullable=False),
    )
    op.create_index(
        "ix_system_data_objects_data_type", "system_data_objects", ["data_type"]
    )
    _fact_table(
        "system_permissions",
        sa.Column("effect", sa.String(length=20), nullable=False),
    )
    op.create_index("ix_system_permissions_effect", "system_permissions", ["effect"])
    _fact_table(
        "system_capabilities",
        sa.Column("capability_type", sa.String(length=50), nullable=False),
    )
    op.create_index(
        "ix_system_capabilities_capability_type",
        "system_capabilities",
        ["capability_type"],
    )
    _fact_table(
        "system_trust_boundaries",
        sa.Column("boundary_type", sa.String(length=50), nullable=False),
    )
    op.create_index(
        "ix_system_trust_boundaries_boundary_type",
        "system_trust_boundaries",
        ["boundary_type"],
    )
    op.create_table(
        "system_relationships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("canonical_identifier", sa.String(length=2048), nullable=False),
        sa.Column("source_entity_type", sa.String(length=40), nullable=False),
        sa.Column("source_entity_id", sa.String(length=36), nullable=False),
        sa.Column("relationship_type", sa.String(length=50), nullable=False),
        sa.Column("target_entity_type", sa.String(length=40), nullable=False),
        sa.Column("target_entity_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "research_session_id",
            "source_entity_type",
            "source_entity_id",
            "relationship_type",
            "target_entity_type",
            "target_entity_id",
            name="uq_system_relationship_semantic_key",
        ),
    )
    for column in (
        "research_session_id",
        "canonical_identifier",
        "source_entity_type",
        "source_entity_id",
        "relationship_type",
        "target_entity_type",
        "target_entity_id",
    ):
        op.create_index(f"ix_system_relationships_{column}", "system_relationships", [column])
    op.create_table(
        "system_model_builds",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("started_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("research_session_id", "status", "started_at"):
        op.create_index(f"ix_system_model_builds_{column}", "system_model_builds", [column])
    op.create_table(
        "system_model_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("research_session_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("build_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["research_session_id"], ["research_sessions.id"]),
        sa.ForeignKeyConstraint(["observation_id"], ["observations.id"]),
        sa.ForeignKeyConstraint(["build_id"], ["system_model_builds.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("research_session_id", "observation_id"),
    )
    for column in ("research_session_id", "observation_id", "build_id"):
        op.create_index(
            f"ix_system_model_observations_{column}",
            "system_model_observations",
            [column],
        )


def downgrade() -> None:
    op.drop_table("system_model_observations")
    op.drop_table("system_model_builds")
    op.drop_table("system_relationships")
    op.drop_table("system_trust_boundaries")
    op.drop_table("system_capabilities")
    op.drop_table("system_permissions")
    op.drop_table("system_data_objects")
    op.drop_table("system_identities")
    op.drop_table("system_roles")
    op.drop_table("system_endpoints")
    op.drop_table("system_services")
    op.drop_table("system_assets")

