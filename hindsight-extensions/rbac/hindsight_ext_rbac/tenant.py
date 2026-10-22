"""Tenant extension: turn a bearer credential into a principal.

Every bank stays in the one configured schema; this extension only answers *who* is
calling, by putting the principal id on ``RequestContext.tenant_id`` (``"anonymous"``
in optional mode). The operation validator decides what that principal may do.

Configuration (``HINDSIGHT_API_TENANT_*``):
    EXTENSION=hindsight_ext_rbac:RbacTenantExtension
    AUTH_MODE=optional|required           default required
    OIDC_ISSUER=https://accounts.google.com
    OIDC_AUDIENCES=<client id>[,...]
    ALLOWED_EMAIL_DOMAINS=firefly.ai[,...]
    ADMIN_EMAILS=a@firefly.ai[,...]       bootstrap admins (cannot be demoted in the UI)
"""

from __future__ import annotations

import os
from pathlib import Path

from hindsight_api.config import HindsightConfig, get_config
from hindsight_api.extensions.bank_tables import BankScopedTable
from hindsight_api.extensions.tenant import AuthenticationError, Tenant, TenantContext, TenantExtension
from hindsight_api.models import RequestContext

from hindsight_ext_rbac.identity import CredentialError, OidcVerifier, is_api_token
from hindsight_ext_rbac.policy import ANONYMOUS
from hindsight_ext_rbac.schema import RBAC_BANK_TABLES
from hindsight_ext_rbac.store import RbacStore, hash_token

_AUTH_MODES = ("optional", "required")
# Only an admin may switch auditing off for a bank.
_ADMIN_ONLY_CONFIG_FIELDS = frozenset({"audit_log_enabled"})


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


class RbacTenantExtension(TenantExtension):
    def __init__(self, config: dict[str, str]) -> None:
        super().__init__(config)
        if os.environ.get("HINDSIGHT_API_MCP_AUTH_TOKEN"):
            raise ValueError(
                "HINDSIGHT_API_MCP_AUTH_TOKEN bypasses per-principal authentication and cannot be used with "
                "the RBAC extension. Remove it; MCP clients authenticate with their own API token."
            )
        self._auth_mode = config.get("auth_mode", "required").strip().lower()
        if self._auth_mode not in _AUTH_MODES:
            raise ValueError(f"HINDSIGHT_API_TENANT_AUTH_MODE must be one of {_AUTH_MODES}, got {self._auth_mode!r}")
        self._admin_emails = {e.lower() for e in _csv(config.get("admin_emails"))}
        self._schema = config.get("schema") or get_config().database_schema

        issuer = (config.get("oidc_issuer") or "").strip()
        self._verifier: OidcVerifier | None = None
        if issuer:
            audiences, domains = _csv(config.get("oidc_audiences")), _csv(config.get("allowed_email_domains"))
            if not audiences or not domains:
                raise ValueError(
                    "HINDSIGHT_API_TENANT_OIDC_ISSUER requires HINDSIGHT_API_TENANT_OIDC_AUDIENCES and "
                    "HINDSIGHT_API_TENANT_ALLOWED_EMAIL_DOMAINS"
                )
            self._verifier = OidcVerifier(issuer=issuer, audiences=audiences, allowed_domains=domains)
        self._store: RbacStore | None = None

    @classmethod
    def alembic_version_locations(cls) -> list[str]:
        return [str(Path(__file__).parent / "alembic_versions")]

    @property
    def store(self) -> RbacStore:
        if self._store is None:
            engine = self.context.get_memory_engine()
            self._store = RbacStore(engine._get_pool)  # type: ignore[attr-defined]
        return self._store

    async def on_startup(self) -> None:
        if self._verifier is not None:
            await self._verifier.start()

    async def on_shutdown(self) -> None:
        if self._verifier is not None:
            await self._verifier.close()

    async def authenticate(self, context: RequestContext) -> TenantContext:
        credential = context.api_key
        if not credential:
            if self._auth_mode == "required":
                raise AuthenticationError("Missing credentials. Expected: Authorization: Bearer <token>")
            context.tenant_id, context.api_key_id = ANONYMOUS.id, None
            return TenantContext(schema_name=self._schema)

        if is_api_token(credential):
            found = await self.store.principal_by_token_hash(hash_token(credential))
            if found is None:
                raise AuthenticationError("Invalid, expired or revoked token")
            principal, token_id = found
            context.tenant_id, context.api_key_id = principal.id, token_id
            return TenantContext(schema_name=self._schema)

        if self._verifier is None:
            raise AuthenticationError("Invalid credentials")
        try:
            identity = await self._verifier.verify(credential)
        except CredentialError as e:
            raise AuthenticationError(str(e)) from e
        principal = await self.store.upsert_oidc_user(
            identity.email, identity.name, is_bootstrap_admin=identity.email in self._admin_emails
        )
        if principal is None:
            raise AuthenticationError("Account disabled")
        context.tenant_id, context.api_key_id = principal.id, "oidc"
        return TenantContext(schema_name=self._schema)

    async def authenticate_mcp(self, context: RequestContext) -> TenantContext:
        return await self.authenticate(context)

    async def list_tenants(self) -> list[Tenant]:
        return [Tenant(schema=self._schema)]

    async def get_allowed_config_fields(self, context: RequestContext, bank_id: str) -> set[str] | None:
        # Core fails open if this raises, so any doubt answers with the restricted set.
        try:
            principal = await self.store.get_principal(context.tenant_id or "")
        except Exception:  # noqa: BLE001 - restricted set below is the safe answer
            principal = None
        if principal is not None and principal.is_admin:
            return None
        return HindsightConfig.get_configurable_fields() - _ADMIN_ONLY_CONFIG_FIELDS

    def extra_bank_tables(self) -> list[BankScopedTable]:
        return list(RBAC_BANK_TABLES)
