"""The RBAC extension's Alembic tree is collected, applied with core's, and makes
every bank that existed before RBAC public with no owner (today's open access)."""

import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from hindsight_api.extensions.loader import EXTENSION_KINDS, collect_alembic_version_locations

RBAC_TENANT = "hindsight_ext_rbac:RbacTenantExtension"


@pytest.fixture(autouse=True)
def _only_rbac_extension(monkeypatch):
    for kind in EXTENSION_KINDS:
        monkeypatch.delenv(f"HINDSIGHT_API_{kind.prefix}_EXTENSION", raising=False)


def test_extension_tree_is_collected(monkeypatch):
    import hindsight_ext_rbac

    monkeypatch.setenv("HINDSIGHT_API_TENANT_EXTENSION", RBAC_TENANT)
    expected = (Path(hindsight_ext_rbac.__file__).parent / "alembic_versions").resolve()
    assert collect_alembic_version_locations() == [str(expected)]


def test_backfill_makes_existing_banks_public(monkeypatch, pg0_db_url):
    from hindsight_api.migrations import run_migrations

    schema = f"rbac_mig_{uuid.uuid4().hex[:8]}"
    run_migrations(pg0_db_url, schema=schema)
    engine = create_engine(pg0_db_url)
    with engine.begin() as conn:
        conn.execute(text(f'INSERT INTO "{schema}".banks (bank_id) VALUES (:a), (:b)'), {"a": "pre-1", "b": "pre-2"})

    monkeypatch.setenv("HINDSIGHT_API_TENANT_EXTENSION", RBAC_TENANT)
    run_migrations(pg0_db_url, schema=schema)

    with engine.connect() as conn:
        rows = conn.execute(
            text(f'SELECT bank_id, visibility, owner_id FROM "{schema}".rbac_bank_acl ORDER BY bank_id')
        ).all()
        tables = {
            r[0]
            for r in conn.execute(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = :s"), {"s": schema}
            )
        }
    assert [tuple(r) for r in rows] == [("pre-1", "public", None), ("pre-2", "public", None)]
    assert {
        "rbac_principals",
        "rbac_tokens",
        "rbac_teams",
        "rbac_team_members",
        "rbac_bank_acl",
        "rbac_bank_grants",
    } <= tables
