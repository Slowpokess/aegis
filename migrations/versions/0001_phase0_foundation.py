"""Create Phase 0 domain tables."""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0001_phase0"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _payload_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    ]


def upgrade() -> None:
    op.create_table("assets", *_payload_columns())
    op.create_table(
        "hypotheses",
        *_payload_columns(),
        sa.Column("status", sa.String(length=20), nullable=False),
    )
    op.create_index("ix_hypotheses_status", "hypotheses", ["status"])
    op.create_table(
        "identities",
        *_payload_columns(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
    )
    op.create_index("ix_identities_asset_id", "identities", ["asset_id"])
    op.create_table(
        "observations",
        *_payload_columns(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
    )
    op.create_index("ix_observations_asset_id", "observations", ["asset_id"])
    op.create_table(
        "experiments",
        *_payload_columns(),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"]),
    )
    op.create_index("ix_experiments_hypothesis_id", "experiments", ["hypothesis_id"])
    op.create_table(
        "capabilities",
        *_payload_columns(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("identity_id", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"]),
    )
    op.create_index("ix_capabilities_asset_id", "capabilities", ["asset_id"])
    op.create_index("ix_capabilities_identity_id", "capabilities", ["identity_id"])
    op.create_table(
        "evidence",
        *_payload_columns(),
        sa.Column("experiment_id", sa.String(length=36), nullable=False),
        sa.Column("integrity_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["experiment_id"], ["experiments.id"]),
    )
    op.create_index("ix_evidence_experiment_id", "evidence", ["experiment_id"])
    op.create_index("ix_evidence_integrity_hash", "evidence", ["integrity_hash"])
    op.create_table(
        "findings",
        *_payload_columns(),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("verification_status", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"]),
    )
    op.create_index("ix_findings_hypothesis_id", "findings", ["hypothesis_id"])
    op.create_index("ix_findings_verification_status", "findings", ["verification_status"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("evidence")
    op.drop_table("capabilities")
    op.drop_table("experiments")
    op.drop_table("observations")
    op.drop_table("identities")
    op.drop_table("hypotheses")
    op.drop_table("assets")
