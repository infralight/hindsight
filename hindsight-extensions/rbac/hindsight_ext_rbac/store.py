"""Database access for principals, API tokens, teams, and per-bank access.

Every read of principal state goes to the database: disabling a principal or
revoking a token must take effect on the very next request, so nothing here is
cached across requests.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from hindsight_api.engine.schema import fq_table

from hindsight_ext_rbac.policy import ANONYMOUS, BankAcl, Principal, Role

if TYPE_CHECKING:
    import asyncpg

PrincipalType = Literal["principal", "team"]
Visibility = Literal["private", "public"]

TOKEN_PREFIX = "hsp_"
_DISPLAY_PREFIX_LEN = 12


@dataclass(frozen=True)
class PrincipalRow:
    principal: Principal
    disabled: bool
    is_bootstrap_admin: bool
    created_at: datetime
    last_seen_at: datetime | None


@dataclass(frozen=True)
class Team:
    id: str
    name: str


@dataclass(frozen=True)
class TeamWithMembers:
    id: str
    name: str
    members: list[Principal]


@dataclass(frozen=True)
class Directory:
    principals: list[Principal]
    teams: list[Team]


@dataclass(frozen=True)
class NewToken:
    id: str
    name: str
    prefix: str
    token: str
    expires_at: datetime | None


@dataclass(frozen=True)
class TokenRow:
    id: str
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked: bool


@dataclass(frozen=True)
class Grant:
    principal_type: PrincipalType
    principal_id: str
    role: Role
    name: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "surrogateescape")).hexdigest()


def _uuid(value: str) -> uuid.UUID | None:
    """Ids arrive from URLs and tokens; anything that is not a UUID names nothing."""
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        return None


def _principal(row: asyncpg.Record) -> Principal:
    return Principal(
        id=str(row["id"]), kind=row["kind"], is_admin=row["is_admin"], email=row["email"], name=row["name"]
    )


_PRINCIPAL_COLS = "p.id, p.kind, p.email, p.name, p.is_admin"


class RbacStore:
    def __init__(self, pool_getter: Callable[[], Awaitable[asyncpg.Pool]]) -> None:
        self._pool_getter = pool_getter

    async def _pool(self) -> asyncpg.Pool:
        return await self._pool_getter()

    # ------------------------------------------------------------------ principals

    async def get_principal(self, principal_id: str) -> Principal | None:
        pid = _uuid(principal_id)
        if pid is None:
            return None
        pool = await self._pool()
        row = await pool.fetchrow(
            f"SELECT {_PRINCIPAL_COLS} FROM {fq_table('rbac_principals')} p WHERE p.id = $1 AND p.disabled_at IS NULL",
            pid,
        )
        return _principal(row) if row else None

    async def principal_by_token_hash(self, token_hash: str) -> tuple[Principal, str] | None:
        pool = await self._pool()
        row = await pool.fetchrow(
            f"""SELECT {_PRINCIPAL_COLS}, t.id AS token_id
                FROM {fq_table("rbac_tokens")} t JOIN {fq_table("rbac_principals")} p ON p.id = t.principal_id
                WHERE t.token_hash = $1 AND t.revoked_at IS NULL
                  AND (t.expires_at IS NULL OR t.expires_at > now()) AND p.disabled_at IS NULL""",
            token_hash,
        )
        if row is None:
            return None
        await pool.execute(
            f"""UPDATE {fq_table("rbac_tokens")} SET last_used_at = now()
                WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')""",
            row["token_id"],
        )
        return _principal(row), str(row["token_id"])

    async def upsert_oidc_user(self, email: str, name: str, is_bootstrap_admin: bool) -> Principal | None:
        """Create the user on first login; returns None when the user is disabled."""
        pool = await self._pool()
        row = await pool.fetchrow(
            f"""INSERT INTO {fq_table("rbac_principals")} AS p (kind, email, name, is_admin, is_bootstrap_admin, last_seen_at)
                VALUES ('user', $1, $2, $3, $3, now())
                ON CONFLICT (email) DO UPDATE SET
                    name = EXCLUDED.name,
                    last_seen_at = now(),
                    is_bootstrap_admin = EXCLUDED.is_bootstrap_admin,
                    is_admin = p.is_admin OR EXCLUDED.is_bootstrap_admin
                RETURNING {_PRINCIPAL_COLS}, p.disabled_at""",
            email.strip().lower(),
            name,
            is_bootstrap_admin,
        )
        return None if row["disabled_at"] is not None else _principal(row)

    async def create_service_account(self, name: str) -> Principal:
        pool = await self._pool()
        row = await pool.fetchrow(
            f"INSERT INTO {fq_table('rbac_principals')} AS p (kind, name) VALUES ('service', $1) RETURNING {_PRINCIPAL_COLS}",
            name,
        )
        return _principal(row)

    async def get_principal_row(self, principal_id: str) -> PrincipalRow | None:
        """Any principal, disabled or not (admin views)."""
        pid = _uuid(principal_id)
        if pid is None:
            return None
        pool = await self._pool()
        row = await pool.fetchrow(
            f"""SELECT {_PRINCIPAL_COLS}, p.disabled_at, p.is_bootstrap_admin, p.created_at, p.last_seen_at
                FROM {fq_table("rbac_principals")} p WHERE p.id = $1""",
            pid,
        )
        return self._principal_row(row) if row else None

    async def list_principals(self) -> list[PrincipalRow]:
        pool = await self._pool()
        rows = await pool.fetch(
            f"""SELECT {_PRINCIPAL_COLS}, p.disabled_at, p.is_bootstrap_admin, p.created_at, p.last_seen_at
                FROM {fq_table("rbac_principals")} p ORDER BY p.kind, p.name"""
        )
        return [self._principal_row(r) for r in rows]

    @staticmethod
    def _principal_row(row: asyncpg.Record) -> PrincipalRow:
        return PrincipalRow(
            principal=_principal(row),
            disabled=row["disabled_at"] is not None,
            is_bootstrap_admin=row["is_bootstrap_admin"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
        )

    async def set_admin(self, principal_id: str, is_admin: bool) -> None:
        pid = _uuid(principal_id)
        if pid is None:
            raise ValueError("Unknown principal")
        pool = await self._pool()
        kind = await pool.fetchval(f"SELECT kind FROM {fq_table('rbac_principals')} WHERE id = $1", pid)
        if kind is None:
            raise ValueError("Unknown principal")
        if kind == "service" and is_admin:
            raise ValueError("A service account cannot be an admin")
        await pool.execute(f"UPDATE {fq_table('rbac_principals')} SET is_admin = $2 WHERE id = $1", pid, is_admin)

    async def set_disabled(self, principal_id: str, disabled: bool) -> None:
        pid = _uuid(principal_id)
        if pid is None:
            raise ValueError("Unknown principal")
        pool = await self._pool()
        await pool.execute(
            f"UPDATE {fq_table('rbac_principals')} SET disabled_at = CASE WHEN $2 THEN now() ELSE NULL END WHERE id = $1",
            pid,
            disabled,
        )

    async def search_directory(self, q: str, limit: int = 20) -> Directory:
        pattern = f"%{q.strip().lower()}%"
        pool = await self._pool()
        principals = await pool.fetch(
            f"""SELECT {_PRINCIPAL_COLS} FROM {fq_table("rbac_principals")} p
                WHERE p.disabled_at IS NULL AND (lower(p.name) LIKE $1 OR coalesce(p.email, '') LIKE $1)
                ORDER BY p.name LIMIT $2""",
            pattern,
            limit,
        )
        teams = await pool.fetch(
            f"SELECT id, name FROM {fq_table('rbac_teams')} WHERE lower(name) LIKE $1 ORDER BY name LIMIT $2",
            pattern,
            limit,
        )
        return Directory(
            principals=[_principal(r) for r in principals], teams=[Team(id=str(r["id"]), name=r["name"]) for r in teams]
        )

    # ------------------------------------------------------------------ tokens

    async def create_token(self, principal_id: str, name: str, expires_at: datetime | None) -> NewToken:
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        prefix = token[:_DISPLAY_PREFIX_LEN]
        pool = await self._pool()
        row = await pool.fetchrow(
            f"""INSERT INTO {fq_table("rbac_tokens")} (principal_id, name, token_hash, prefix, expires_at)
                VALUES ($1, $2, $3, $4, $5) RETURNING id""",
            uuid.UUID(principal_id),
            name,
            hash_token(token),
            prefix,
            expires_at,
        )
        return NewToken(id=str(row["id"]), name=name, prefix=prefix, token=token, expires_at=expires_at)

    async def list_tokens(self, principal_id: str) -> list[TokenRow]:
        pid = _uuid(principal_id)
        if pid is None:
            return []
        pool = await self._pool()
        rows = await pool.fetch(
            f"""SELECT id, name, prefix, created_at, expires_at, last_used_at, revoked_at
                FROM {fq_table("rbac_tokens")} WHERE principal_id = $1 ORDER BY created_at DESC""",
            pid,
        )
        return [
            TokenRow(
                id=str(r["id"]),
                name=r["name"],
                prefix=r["prefix"],
                created_at=r["created_at"],
                expires_at=r["expires_at"],
                last_used_at=r["last_used_at"],
                revoked=r["revoked_at"] is not None,
            )
            for r in rows
        ]

    async def revoke_token(self, token_id: str, principal_id: str | None) -> bool:
        """Revoke a token; ``principal_id=None`` is the admin path (any owner)."""
        tid = _uuid(token_id)
        if tid is None:
            return False
        pool = await self._pool()
        if principal_id is None:
            result = await pool.execute(
                f"UPDATE {fq_table('rbac_tokens')} SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", tid
            )
        else:
            pid = _uuid(principal_id)
            if pid is None:
                return False
            result = await pool.execute(
                f"""UPDATE {fq_table("rbac_tokens")} SET revoked_at = now()
                    WHERE id = $1 AND principal_id = $2 AND revoked_at IS NULL""",
                tid,
                pid,
            )
        return result == "UPDATE 1"

    # ------------------------------------------------------------------ teams

    async def create_team(self, name: str) -> Team:
        pool = await self._pool()
        row = await pool.fetchrow(f"INSERT INTO {fq_table('rbac_teams')} (name) VALUES ($1) RETURNING id, name", name)
        return Team(id=str(row["id"]), name=row["name"])

    async def get_team(self, team_id: str) -> Team | None:
        tid = _uuid(team_id)
        if tid is None:
            return None
        pool = await self._pool()
        row = await pool.fetchrow(f"SELECT id, name FROM {fq_table('rbac_teams')} WHERE id = $1", tid)
        return Team(id=str(row["id"]), name=row["name"]) if row else None

    async def rename_team(self, team_id: str, name: str) -> bool:
        tid = _uuid(team_id)
        if tid is None:
            return False
        pool = await self._pool()
        return await pool.execute(f"UPDATE {fq_table('rbac_teams')} SET name = $2 WHERE id = $1", tid, name) == (
            "UPDATE 1"
        )

    async def delete_team(self, team_id: str) -> bool:
        tid = _uuid(team_id)
        if tid is None:
            return False
        pool = await self._pool()
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute(
                f"DELETE FROM {fq_table('rbac_bank_grants')} WHERE principal_type = 'team' AND principal_id = $1", tid
            )
            result = await conn.execute(f"DELETE FROM {fq_table('rbac_teams')} WHERE id = $1", tid)
        return result == "DELETE 1"

    async def list_teams(self) -> list[TeamWithMembers]:
        pool = await self._pool()
        teams = await pool.fetch(f"SELECT id, name FROM {fq_table('rbac_teams')} ORDER BY name")
        members = await pool.fetch(
            f"""SELECT m.team_id, {_PRINCIPAL_COLS} FROM {fq_table("rbac_team_members")} m
                JOIN {fq_table("rbac_principals")} p ON p.id = m.principal_id ORDER BY p.name"""
        )
        by_team: dict[uuid.UUID, list[Principal]] = {}
        for r in members:
            by_team.setdefault(r["team_id"], []).append(_principal(r))
        return [TeamWithMembers(id=str(t["id"]), name=t["name"], members=by_team.get(t["id"], [])) for t in teams]

    async def add_member(self, team_id: str, principal_id: str) -> None:
        pool = await self._pool()
        await pool.execute(
            f"INSERT INTO {fq_table('rbac_team_members')} (team_id, principal_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            uuid.UUID(team_id),
            uuid.UUID(principal_id),
        )

    async def remove_member(self, team_id: str, principal_id: str) -> None:
        tid, pid = _uuid(team_id), _uuid(principal_id)
        if tid is None or pid is None:
            return
        pool = await self._pool()
        await pool.execute(
            f"DELETE FROM {fq_table('rbac_team_members')} WHERE team_id = $1 AND principal_id = $2", tid, pid
        )

    # ------------------------------------------------------------------ bank access

    async def get_acl(self, bank_id: str) -> BankAcl | None:
        pool = await self._pool()
        row = await pool.fetchrow(
            f"SELECT bank_id, visibility, owner_id FROM {fq_table('rbac_bank_acl')} WHERE bank_id = $1", bank_id
        )
        if row is None:
            return None
        owner = str(row["owner_id"]) if row["owner_id"] is not None else None
        return BankAcl(bank_id=row["bank_id"], visibility=row["visibility"], owner_id=owner)

    async def grant_roles(self, bank_id: str, principal_id: str) -> list[Role]:
        pid = _uuid(principal_id)
        if pid is None:
            return []
        pool = await self._pool()
        rows = await pool.fetch(
            f"""SELECT g.role FROM {fq_table("rbac_bank_grants")} g
                WHERE g.bank_id = $1 AND (
                    (g.principal_type = 'principal' AND g.principal_id = $2)
                    OR (g.principal_type = 'team' AND g.principal_id IN (
                        SELECT team_id FROM {fq_table("rbac_team_members")} WHERE principal_id = $2)))""",
            bank_id,
            pid,
        )
        return [Role(r["role"]) for r in rows]

    async def record_new_bank(self, bank_id: str, owner_id: str | None) -> None:
        """First writer wins: concurrent first creates may all get here; one row survives."""
        pool = await self._pool()
        await pool.execute(
            f"""INSERT INTO {fq_table("rbac_bank_acl")} (bank_id, visibility, owner_id) VALUES ($1, 'public', $2)
                ON CONFLICT (bank_id) DO NOTHING""",
            bank_id,
            _uuid(owner_id) if owner_id else None,
        )

    async def set_visibility(self, bank_id: str, visibility: Visibility) -> None:
        pool = await self._pool()
        await pool.execute(
            f"UPDATE {fq_table('rbac_bank_acl')} SET visibility = $2, updated_at = now() WHERE bank_id = $1",
            bank_id,
            visibility,
        )

    async def set_owner(self, bank_id: str, owner_id: str | None) -> None:
        pool = await self._pool()
        await pool.execute(
            f"UPDATE {fq_table('rbac_bank_acl')} SET owner_id = $2, updated_at = now() WHERE bank_id = $1",
            bank_id,
            _uuid(owner_id) if owner_id else None,
        )

    async def list_grants(self, bank_id: str) -> list[Grant]:
        pool = await self._pool()
        rows = await pool.fetch(
            f"""SELECT g.principal_type, g.principal_id, g.role, coalesce(p.name, t.name, '?') AS name
                FROM {fq_table("rbac_bank_grants")} g
                LEFT JOIN {fq_table("rbac_principals")} p ON g.principal_type = 'principal' AND p.id = g.principal_id
                LEFT JOIN {fq_table("rbac_teams")} t ON g.principal_type = 'team' AND t.id = g.principal_id
                WHERE g.bank_id = $1 ORDER BY g.principal_type, name""",
            bank_id,
        )
        return [
            Grant(
                principal_type=r["principal_type"],
                principal_id=str(r["principal_id"]),
                role=Role(r["role"]),
                name=r["name"],
            )
            for r in rows
        ]

    async def put_grant(self, bank_id: str, principal_type: PrincipalType, principal_id: str, role: Role) -> None:
        pool = await self._pool()
        await pool.execute(
            f"""INSERT INTO {fq_table("rbac_bank_grants")} (bank_id, principal_type, principal_id, role)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (bank_id, principal_type, principal_id) DO UPDATE SET role = EXCLUDED.role""",
            bank_id,
            principal_type,
            uuid.UUID(principal_id),
            role.value,
        )

    async def delete_grant(self, bank_id: str, principal_type: PrincipalType, principal_id: str) -> bool:
        pid = _uuid(principal_id)
        if pid is None:
            return False
        pool = await self._pool()
        result = await pool.execute(
            f"""DELETE FROM {fq_table("rbac_bank_grants")}
                WHERE bank_id = $1 AND principal_type = $2 AND principal_id = $3""",
            bank_id,
            principal_type,
            pid,
        )
        return result == "DELETE 1"

    async def readable_bank_ids(self, principal_id: str) -> list[str]:
        """Banks the principal can at least read: public, owned, or granted directly or via a team."""
        pool = await self._pool()
        pid = None if principal_id == ANONYMOUS.id else _uuid(principal_id)
        if pid is None:
            rows = await pool.fetch(f"SELECT bank_id FROM {fq_table('rbac_bank_acl')} WHERE visibility = 'public'")
            return [r["bank_id"] for r in rows]
        rows = await pool.fetch(
            f"""SELECT a.bank_id FROM {fq_table("rbac_bank_acl")} a
                WHERE a.visibility = 'public' OR a.owner_id = $1
                UNION
                SELECT g.bank_id FROM {fq_table("rbac_bank_grants")} g
                WHERE (g.principal_type = 'principal' AND g.principal_id = $1)
                   OR (g.principal_type = 'team' AND g.principal_id IN (
                        SELECT team_id FROM {fq_table("rbac_team_members")} WHERE principal_id = $1))""",
            pid,
        )
        return [r["bank_id"] for r in rows]
