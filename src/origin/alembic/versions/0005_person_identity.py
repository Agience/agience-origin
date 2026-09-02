"""person_identities — many identities per person; drop the single-slot OIDC columns.

Revision ID: 0005_person_identity
Revises: 0004_passkey_challenges

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_person_identity"
down_revision: Union[str, None] = "0004_passkey_challenges"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "person_identities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("person_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=256), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("proof", sa.Text(), nullable=True),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("modified_time", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["person_id"], ["persons.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_person_identities_person_id", "person_identities", ["person_id"])
    op.create_index("ux_person_identity", "person_identities",
                    ["method", "provider", "subject"], unique=True)
    op.create_index("ix_person_identity_lookup", "person_identities", ["provider", "subject"])

    # ── backfill: the OIDC pair ───────────────────────────────────────────────────────────────
    op.execute(sa.text("""
        INSERT INTO person_identities
            (id, person_id, method, provider, subject, verified_at, created_time, modified_time)
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
               substr(lower(hex(randomblob(2))),2) || '-a' ||
               substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6))),
               id, 'oidc', oidc_provider, oidc_subject, created_time, created_time, created_time
        FROM persons
        WHERE oidc_provider IS NOT NULL AND oidc_subject IS NOT NULL
    """))

    # ── backfill: the vestigial google_id, only where it is not already covered ───────────────
    op.execute(sa.text("""
        INSERT INTO person_identities
            (id, person_id, method, provider, subject, verified_at, created_time, modified_time)
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
               substr(lower(hex(randomblob(2))),2) || '-a' ||
               substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6))),
               id, 'oidc', 'google', google_id, created_time, created_time, created_time
        FROM persons
        WHERE google_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM person_identities pi
              WHERE pi.method = 'oidc' AND pi.provider = 'google' AND pi.subject = persons.google_id
          )
    """))

    # ── only now is it safe to drop the single-slot columns ──────────────────────────────────
    with op.batch_alter_table("persons") as batch:
        batch.drop_index("ix_persons_oidc_identity")
        batch.drop_index("ix_persons_google_id")
        batch.drop_column("oidc_provider")
        batch.drop_column("oidc_subject")
        batch.drop_column("google_id")


def downgrade() -> None:
    """Restore the single-slot columns and repopulate one OIDC identity per person.

    Lossy when a person has more than one OIDC identity: only the earliest by
    `created_time` is restored, and non-OIDC identities (passkeys, etc.) are
    not represented in the restored columns at all.
    """
    with op.batch_alter_table("persons") as batch:
        batch.add_column(sa.Column("oidc_provider", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("oidc_subject", sa.String(length=256), nullable=True))
        batch.add_column(sa.Column("google_id", sa.String(length=256), nullable=True))

    op.execute(sa.text("""
        UPDATE persons SET
          oidc_provider = (SELECT pi.provider FROM person_identities pi
                           WHERE pi.person_id = persons.id AND pi.method = 'oidc'
                           ORDER BY pi.created_time LIMIT 1),
          oidc_subject  = (SELECT pi.subject FROM person_identities pi
                           WHERE pi.person_id = persons.id AND pi.method = 'oidc'
                           ORDER BY pi.created_time LIMIT 1)
    """))
    op.execute(sa.text("""
        UPDATE persons SET google_id = oidc_subject WHERE oidc_provider = 'google'
    """))

    op.create_index("ix_persons_oidc_identity", "persons", ["oidc_provider", "oidc_subject"],
                    unique=True, sqlite_where=sa.text("oidc_provider IS NOT NULL"))
    op.create_index("ix_persons_google_id", "persons", ["google_id"])

    op.drop_index("ix_person_identity_lookup", table_name="person_identities")
    op.drop_index("ux_person_identity", table_name="person_identities")
    op.drop_index("ix_person_identities_person_id", table_name="person_identities")
    op.drop_table("person_identities")
