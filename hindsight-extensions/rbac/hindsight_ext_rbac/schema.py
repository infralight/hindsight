"""RBAC tables: principals, API tokens, teams, and per-bank access.

The DDL lives here once and is applied by the extension's Alembic revision (and by
tests, which build engines without running migrations). PostgreSQL only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hindsight_api.extensions.bank_tables import BankScopedTable

if TYPE_CHECKING:
    import asyncpg

# Bank-scoped rows core must sweep on bank deletion and include in backups.
RBAC_BANK_TABLES = [BankScopedTable("rbac_bank_acl"), BankScopedTable("rbac_bank_grants")]

_TABLES = ("rbac_bank_grants", "rbac_bank_acl", "rbac_team_members", "rbac_teams", "rbac_tokens", "rbac_principals")


def ddl(p: str) -> list[str]:
    """CREATE statements with ``p`` (e.g. ``'"public".'`` or ``""``) prefixed to every table."""
    return [
        f"""CREATE TABLE IF NOT EXISTS {p}rbac_principals (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            kind text NOT NULL CHECK (kind IN ('user', 'service')),
            email text UNIQUE,
            name text NOT NULL,
            is_admin boolean NOT NULL DEFAULT false,
            is_bootstrap_admin boolean NOT NULL DEFAULT false,
            disabled_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            last_seen_at timestamptz,
            CHECK (NOT (kind = 'service' AND is_admin))
        )""",
        f"""CREATE TABLE IF NOT EXISTS {p}rbac_tokens (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            principal_id uuid NOT NULL REFERENCES {p}rbac_principals (id) ON DELETE CASCADE,
            name text NOT NULL,
            token_hash text NOT NULL UNIQUE,
            prefix text NOT NULL,
            expires_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            last_used_at timestamptz,
            revoked_at timestamptz
        )""",
        f"""CREATE TABLE IF NOT EXISTS {p}rbac_teams (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            name text NOT NULL UNIQUE,
            created_at timestamptz NOT NULL DEFAULT now()
        )""",
        f"""CREATE TABLE IF NOT EXISTS {p}rbac_team_members (
            team_id uuid NOT NULL REFERENCES {p}rbac_teams (id) ON DELETE CASCADE,
            principal_id uuid NOT NULL REFERENCES {p}rbac_principals (id) ON DELETE CASCADE,
            PRIMARY KEY (team_id, principal_id)
        )""",
        # No FK to banks: the row is written by validate_create_bank, before the bank row exists.
        f"""CREATE TABLE IF NOT EXISTS {p}rbac_bank_acl (
            bank_id text PRIMARY KEY,
            visibility text NOT NULL CHECK (visibility IN ('private', 'public')),
            owner_id uuid REFERENCES {p}rbac_principals (id) ON DELETE SET NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )""",
        f"""CREATE TABLE IF NOT EXISTS {p}rbac_bank_grants (
            bank_id text NOT NULL,
            principal_type text NOT NULL CHECK (principal_type IN ('principal', 'team')),
            principal_id uuid NOT NULL,
            role text NOT NULL CHECK (role IN ('reader', 'writer', 'owner')),
            PRIMARY KEY (bank_id, principal_type, principal_id)
        )""",
        f"CREATE INDEX IF NOT EXISTS ix_rbac_bank_grants_principal ON {p}rbac_bank_grants (principal_type, principal_id)",
    ]


def backfill_existing_banks(p: str) -> str:
    """Banks that predate RBAC were open to everyone: keep them that way, ownerless."""
    return (
        f"INSERT INTO {p}rbac_bank_acl (bank_id, visibility, owner_id) "
        f"SELECT bank_id, 'public', NULL FROM {p}banks ON CONFLICT (bank_id) DO NOTHING"
    )


def drop(p: str) -> list[str]:
    return [f"DROP TABLE IF EXISTS {p}{t}" for t in _TABLES]


async def ensure_schema(conn: asyncpg.Connection, schema: str) -> None:
    """Create the RBAC tables in ``schema`` (idempotent); used where migrations do not run."""
    for statement in ddl(f'"{schema}".'):
        await conn.execute(statement)
