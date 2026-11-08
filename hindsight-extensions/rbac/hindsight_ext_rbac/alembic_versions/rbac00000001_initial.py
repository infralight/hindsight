"""RBAC tables, and every pre-existing bank made public with no owner

PostgreSQL only: the fork's RBAC does not support Oracle, so the oracle slot is
deliberately absent.

Revision ID: rbac00000001
Revises:
Create Date: 2026-10-22
"""

from collections.abc import Sequence

from alembic import context, op
from hindsight_api.alembic._dialect import run_for_dialect
from hindsight_ext_rbac.schema import backfill_existing_banks, ddl, drop

revision: str = "rbac00000001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = ("rbac",)
# The core revision that creates `banks`, which the backfill reads.
depends_on: str | Sequence[str] | None = ("5a366d414dce",)


def _pg_schema_prefix() -> str:
    schema = context.config.get_main_option("target_schema")
    return f'"{schema}".' if schema else ""


def _pg_upgrade() -> None:
    prefix = _pg_schema_prefix()
    for statement in ddl(prefix):
        op.execute(statement)
    op.execute(backfill_existing_banks(prefix))


def _pg_downgrade() -> None:
    for statement in drop(_pg_schema_prefix()):
        op.execute(statement)


def upgrade() -> None:
    run_for_dialect(pg=_pg_upgrade)


def downgrade() -> None:
    run_for_dialect(pg=_pg_downgrade)
