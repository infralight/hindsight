"""HTTP extension: /ext/rbac management API for tokens, principals, teams and bank sharing.

Every route requires an authenticated (non-anonymous) principal. Bank routes answer
404/403 by the same rule as the operation validator, and core canonicalizes aliased
``{bank_id}`` path params on these routes too.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from hindsight_api.engine.audit import AuditEntry
from hindsight_api.extensions.http import HttpExtension
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext
from pydantic import BaseModel, Field

from hindsight_ext_rbac.policy import ANONYMOUS, Capability, Principal, Role, effective_role
from hindsight_ext_rbac.store import NewToken, PrincipalRow, RbacStore, TokenRow
from hindsight_ext_rbac.validator import CallerError, bank_capabilities, denial, resolve_caller

# ------------------------------------------------------------------ schemas


class PrincipalOut(BaseModel):
    id: str
    kind: str
    email: str | None
    name: str
    is_admin: bool


class PrincipalAdminOut(PrincipalOut):
    disabled: bool
    is_bootstrap_admin: bool
    created_at: datetime
    last_seen_at: datetime | None


class PrincipalList(BaseModel):
    principals: list[PrincipalAdminOut]


class PrincipalPatch(BaseModel):
    is_admin: bool | None = None
    disabled: bool | None = None


class ServiceAccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    expires_at: datetime | None = None


class TokenCreated(BaseModel):
    id: str
    name: str
    prefix: str
    token: str
    expires_at: datetime | None


class TokenOut(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked: bool


class TokenList(BaseModel):
    tokens: list[TokenOut]


class TeamIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class TeamOut(BaseModel):
    id: str
    name: str


class TeamWithMembersOut(TeamOut):
    members: list[PrincipalOut]


class TeamList(BaseModel):
    teams: list[TeamWithMembersOut]


class Directory(BaseModel):
    principals: list[PrincipalOut]
    teams: list[TeamOut]


class GrantIn(BaseModel):
    principal_type: Literal["principal", "team"]
    principal_id: str
    role: Role


class GrantOut(BaseModel):
    principal_type: Literal["principal", "team"]
    principal_id: str
    name: str
    role: Role


class AccessPatch(BaseModel):
    visibility: Literal["private", "public"] | None = None
    owner_id: str | None = None


class BankAccess(BaseModel):
    bank_id: str
    visibility: Literal["private", "public"]
    owner: PrincipalOut | None
    grants: list[GrantOut]
    my_role: Role | None
    my_capabilities: list[Capability]


def _out(p: Principal) -> PrincipalOut:
    return PrincipalOut(id=p.id, kind=p.kind, email=p.email, name=p.name, is_admin=p.is_admin)


def _admin_out(row: PrincipalRow) -> PrincipalAdminOut:
    return PrincipalAdminOut(
        **_out(row.principal).model_dump(),
        disabled=row.disabled,
        is_bootstrap_admin=row.is_bootstrap_admin,
        created_at=row.created_at,
        last_seen_at=row.last_seen_at,
    )


def _token_out(t: TokenRow) -> TokenOut:
    return TokenOut(**t.__dict__)


def _created(t: NewToken) -> TokenCreated:
    return TokenCreated(**t.__dict__)


# ------------------------------------------------------------------ extension


class RbacHttpExtension(HttpExtension):
    def get_router(self, memory: Any) -> APIRouter:
        store = RbacStore(memory._get_pool)
        router = APIRouter(prefix="/rbac", tags=["RBAC"])

        def audit(action: str, actor: Principal, bank_id: str | None, request: dict[str, Any]) -> None:
            audit_logger = getattr(memory, "_audit_logger", None)
            if audit_logger is not None:
                audit_logger.log_fire_and_forget(
                    AuditEntry(
                        action=f"rbac.{action}",
                        transport="http",
                        bank_id=bank_id,
                        request=request,
                        metadata={"actor": actor.id},
                    )
                )

        async def caller(request: Request) -> Principal:
            context = getattr(request.state, "hs_request_context", None)
            if context is None:
                authorization = request.headers.get("authorization") or ""
                api_key = authorization[7:].strip() if authorization.lower().startswith("bearer ") else authorization
                context = RequestContext(api_key=api_key or None)
            try:
                await memory._authenticate_tenant(context)
                principal = await resolve_caller(store, context)
            except AuthenticationError as e:
                raise HTTPException(401, e.reason) from e
            except CallerError as e:
                raise HTTPException(e.status_code, e.reason) from e
            if principal == "system" or principal is ANONYMOUS:
                raise HTTPException(401, "Authentication required")
            return principal  # type: ignore[return-value]

        async def admin(principal: Principal = Depends(caller)) -> Principal:
            if not principal.is_admin:
                raise HTTPException(403, "Admin only")
            return principal

        async def require_on_bank(bank_id: str, principal: Principal, needed: Capability, what: str) -> None:
            caps = await bank_capabilities(store, principal, bank_id)
            refused = denial(bank_id, caps, needed, what)
            if refused is not None:
                raise HTTPException(refused.status_code, refused.reason)

        # ---------------------------------------------------------- self

        @router.get("/me", response_model=PrincipalOut)
        async def me(principal: Principal = Depends(caller)) -> PrincipalOut:
            return _out(principal)

        @router.get("/directory", response_model=Directory)
        async def directory(q: str = "", principal: Principal = Depends(caller)) -> Directory:
            found = await store.search_directory(q)
            return Directory(
                principals=[_out(p) for p in found.principals],
                teams=[TeamOut(id=t.id, name=t.name) for t in found.teams],
            )

        @router.get("/tokens", response_model=TokenList)
        async def list_my_tokens(principal: Principal = Depends(caller)) -> TokenList:
            return TokenList(tokens=[_token_out(t) for t in await store.list_tokens(principal.id)])

        @router.post("/tokens", response_model=TokenCreated, status_code=201)
        async def create_my_token(body: TokenIn, principal: Principal = Depends(caller)) -> TokenCreated:
            token = await store.create_token(principal.id, body.name, body.expires_at)
            audit("create_token", principal, None, {"token_id": token.id, "name": body.name})
            return _created(token)

        @router.delete("/tokens/{token_id}", status_code=204)
        async def revoke_token(token_id: str, principal: Principal = Depends(caller)) -> Response:
            owner = None if principal.is_admin else principal.id
            if not await store.revoke_token(token_id, owner):
                raise HTTPException(404, "Token not found")
            audit("revoke_token", principal, None, {"token_id": token_id})
            return Response(status_code=204)

        # ---------------------------------------------------------- principals (admin)

        @router.get("/principals", response_model=PrincipalList)
        async def list_principals(principal: Principal = Depends(admin)) -> PrincipalList:
            return PrincipalList(principals=[_admin_out(r) for r in await store.list_principals()])

        @router.patch("/principals/{principal_id}", response_model=PrincipalAdminOut)
        async def update_principal(
            principal_id: str, body: PrincipalPatch, principal: Principal = Depends(admin)
        ) -> PrincipalAdminOut:
            target = await store.get_principal_row(principal_id)
            if target is None:
                raise HTTPException(404, "Principal not found")
            if target.is_bootstrap_admin and (body.is_admin is False or body.disabled is True):
                raise HTTPException(409, "Configured admins cannot be demoted or disabled here")
            if body.is_admin and target.principal.kind == "service":
                raise HTTPException(409, "A service account cannot be an admin")
            if body.is_admin is not None:
                await store.set_admin(principal_id, body.is_admin)
            if body.disabled is not None:
                await store.set_disabled(principal_id, body.disabled)
            audit(
                "update_principal",
                principal,
                None,
                {"principal_id": principal_id, **body.model_dump(exclude_none=True)},
            )
            updated = await store.get_principal_row(principal_id)
            assert updated is not None
            return _admin_out(updated)

        @router.post("/service-accounts", response_model=PrincipalOut, status_code=201)
        async def create_service_account(body: ServiceAccountIn, principal: Principal = Depends(admin)) -> PrincipalOut:
            account = await store.create_service_account(body.name)
            audit("create_service_account", principal, None, {"principal_id": account.id, "name": body.name})
            return _out(account)

        @router.get("/principals/{principal_id}/tokens", response_model=TokenList)
        async def list_principal_tokens(principal_id: str, principal: Principal = Depends(admin)) -> TokenList:
            return TokenList(tokens=[_token_out(t) for t in await store.list_tokens(principal_id)])

        @router.post("/principals/{principal_id}/tokens", response_model=TokenCreated, status_code=201)
        async def mint_service_token(
            principal_id: str, body: TokenIn, principal: Principal = Depends(admin)
        ) -> TokenCreated:
            target = await store.get_principal_row(principal_id)
            if target is None:
                raise HTTPException(404, "Principal not found")
            if target.principal.kind != "service":
                raise HTTPException(409, "Admins mint tokens for service accounts only; users create their own")
            token = await store.create_token(principal_id, body.name, body.expires_at)
            audit("create_token", principal, None, {"principal_id": principal_id, "token_id": token.id})
            return _created(token)

        # ---------------------------------------------------------- teams

        @router.get("/teams", response_model=TeamList)
        async def list_teams(principal: Principal = Depends(caller)) -> TeamList:
            return TeamList(
                teams=[
                    TeamWithMembersOut(id=t.id, name=t.name, members=[_out(m) for m in t.members])
                    for t in await store.list_teams()
                ]
            )

        @router.post("/teams", response_model=TeamOut, status_code=201)
        async def create_team(body: TeamIn, principal: Principal = Depends(admin)) -> TeamOut:
            try:
                team = await store.create_team(body.name)
            except asyncpg.UniqueViolationError as e:
                raise HTTPException(409, "A team with that name exists") from e
            audit("create_team", principal, None, {"team_id": team.id, "name": body.name})
            return TeamOut(id=team.id, name=team.name)

        @router.patch("/teams/{team_id}", response_model=TeamOut)
        async def rename_team(team_id: str, body: TeamIn, principal: Principal = Depends(admin)) -> TeamOut:
            try:
                renamed = await store.rename_team(team_id, body.name)
            except asyncpg.UniqueViolationError as e:
                raise HTTPException(409, "A team with that name exists") from e
            if not renamed:
                raise HTTPException(404, "Team not found")
            audit("rename_team", principal, None, {"team_id": team_id, "name": body.name})
            return TeamOut(id=team_id, name=body.name)

        @router.delete("/teams/{team_id}", status_code=204)
        async def delete_team(team_id: str, principal: Principal = Depends(admin)) -> Response:
            if not await store.delete_team(team_id):
                raise HTTPException(404, "Team not found")
            audit("delete_team", principal, None, {"team_id": team_id})
            return Response(status_code=204)

        @router.put("/teams/{team_id}/members/{principal_id}", status_code=204)
        async def add_member(team_id: str, principal_id: str, principal: Principal = Depends(admin)) -> Response:
            if await store.get_team(team_id) is None or await store.get_principal_row(principal_id) is None:
                raise HTTPException(404, "Team or principal not found")
            await store.add_member(team_id, principal_id)
            audit("add_team_member", principal, None, {"team_id": team_id, "principal_id": principal_id})
            return Response(status_code=204)

        @router.delete("/teams/{team_id}/members/{principal_id}", status_code=204)
        async def remove_member(team_id: str, principal_id: str, principal: Principal = Depends(admin)) -> Response:
            await store.remove_member(team_id, principal_id)
            audit("remove_team_member", principal, None, {"team_id": team_id, "principal_id": principal_id})
            return Response(status_code=204)

        # ---------------------------------------------------------- bank sharing

        async def bank_access(bank_id: str, principal: Principal) -> BankAccess:
            acl = await store.get_acl(bank_id)
            if acl is None:  # admins only get here: a bank row without an ACL row
                raise HTTPException(404, f"Bank '{bank_id}' has no access record")
            owner = await store.get_principal_row(acl.owner_id) if acl.owner_id else None
            grants = await store.list_grants(bank_id)
            role = effective_role(principal, acl, await store.grant_roles(bank_id, principal.id))
            return BankAccess(
                bank_id=bank_id,
                visibility=acl.visibility,
                owner=_out(owner.principal) if owner else None,
                grants=[GrantOut(**g.__dict__) for g in grants],
                my_role=role,
                my_capabilities=sorted(await bank_capabilities(store, principal, bank_id)),
            )

        @router.get("/banks/{bank_id}/access", response_model=BankAccess)
        async def get_access(bank_id: str, principal: Principal = Depends(caller)) -> BankAccess:
            await require_on_bank(bank_id, principal, Capability.READ, "view access")
            return await bank_access(bank_id, principal)

        @router.patch("/banks/{bank_id}/access", response_model=BankAccess)
        async def update_access(bank_id: str, body: AccessPatch, principal: Principal = Depends(caller)) -> BankAccess:
            await require_on_bank(bank_id, principal, Capability.MANAGE, "change access")
            if "owner_id" in body.model_fields_set and body.owner_id is not None:
                if await store.get_principal(body.owner_id) is None:
                    raise HTTPException(404, "New owner not found")
            if body.visibility is not None:
                await store.set_visibility(bank_id, body.visibility)
            if "owner_id" in body.model_fields_set:
                await store.set_owner(bank_id, body.owner_id)
            audit("update_access", principal, bank_id, body.model_dump(exclude_unset=True))
            return await bank_access(bank_id, principal)

        @router.put("/banks/{bank_id}/grants", response_model=BankAccess)
        async def put_grant(bank_id: str, body: GrantIn, principal: Principal = Depends(caller)) -> BankAccess:
            await require_on_bank(bank_id, principal, Capability.MANAGE, "share the bank")
            exists = (
                await store.get_principal(body.principal_id)
                if body.principal_type == "principal"
                else await store.get_team(body.principal_id)
            )
            if exists is None:
                raise HTTPException(404, f"{body.principal_type.title()} not found")
            await store.put_grant(bank_id, body.principal_type, body.principal_id, body.role)
            audit("put_grant", principal, bank_id, body.model_dump(mode="json"))
            return await bank_access(bank_id, principal)

        @router.delete("/banks/{bank_id}/grants/{principal_type}/{principal_id}", status_code=204)
        async def delete_grant(
            bank_id: str,
            principal_type: Literal["principal", "team"],
            principal_id: str,
            principal: Principal = Depends(caller),
        ) -> Response:
            await require_on_bank(bank_id, principal, Capability.MANAGE, "share the bank")
            if not await store.delete_grant(bank_id, principal_type, principal_id):
                raise HTTPException(404, "Grant not found")
            audit("delete_grant", principal, bank_id, {"principal_type": principal_type, "principal_id": principal_id})
            return Response(status_code=204)

        return router
