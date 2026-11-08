"""Operation validator: every engine operation on a bank asks for one capability.

The tenant extension put the caller's principal id on ``RequestContext.tenant_id``;
this resolves it (from the database, every time) to a role on the bank and refuses
what the role does not allow. A bank the caller cannot read answers 404 so private
bank names do not leak; a readable bank answers 403 for a missing capability.

Internal contexts with no principal are system work (maintenance, sweeps) and pass.
Worker jobs a principal queued carry that principal and are checked again when they run.
"""

from __future__ import annotations

import logging
from typing import Literal

from hindsight_api.extensions.operation_validator import (
    BankListScope,
    BankReadContext,
    BankWriteContext,
    ConsolidateContext,
    CreateBankContext,
    ImportContext,
    MemoryUpdateContext,
    MentalModelGetContext,
    MentalModelRefreshContext,
    OperationValidatorExtension,
    RecallContext,
    ReflectContext,
    RetainContext,
    ValidationResult,
)
from hindsight_api.models import RequestContext

from hindsight_ext_rbac.policy import (
    ALL_CAPABILITIES,
    ANONYMOUS,
    MCP_TOOL_CAPABILITY,
    READ_OP_CAPABILITY,
    WRITE_OP_CAPABILITY,
    Capability,
    Principal,
    capabilities,
    effective_role,
)
from hindsight_ext_rbac.store import RbacStore

logger = logging.getLogger(__name__)

_SYSTEM: Literal["system"] = "system"
# Tools that do not act on the session bank: visible to anyone authenticated.
_BANK_AGNOSTIC_TOOLS = frozenset({"list_banks", "create_bank"})


class CallerError(Exception):
    def __init__(self, reason: str, status_code: int) -> None:
        super().__init__(reason)
        self.reason, self.status_code = reason, status_code


async def resolve_caller(store: RbacStore, request_context: RequestContext) -> Principal | Literal["system"]:
    """The principal behind a request, or ``"system"`` for internal work with no principal."""
    principal_id = request_context.tenant_id
    if principal_id is None:
        if request_context.internal:
            return _SYSTEM
        raise CallerError("Missing credentials", 401)
    if principal_id == ANONYMOUS.id:
        return ANONYMOUS
    principal = await store.get_principal(principal_id)
    if principal is None:
        raise CallerError("Unknown or disabled principal", 401)
    return principal


async def bank_capabilities(store: RbacStore, principal: Principal, bank_id: str) -> frozenset[Capability]:
    if principal.is_admin:
        return ALL_CAPABILITIES
    acl = await store.get_acl(bank_id)
    grants = await store.grant_roles(bank_id, principal.id) if principal is not ANONYMOUS and acl else []
    return capabilities(principal, acl, effective_role(principal, acl, grants))


def denial(bank_id: str, caps: frozenset[Capability], needed: Capability, what: str) -> ValidationResult | None:
    """The rejection for a caller holding ``caps`` who needs ``needed``, or None if allowed."""
    if Capability.READ not in caps:
        return ValidationResult.reject(f"Bank '{bank_id}' not found", 404)
    if needed not in caps:
        return ValidationResult.reject(f"You need {needed.value} access on bank '{bank_id}' to {what}", 403)
    return None


class RbacOperationValidator(OperationValidatorExtension):
    def __init__(self, config: dict[str, str]) -> None:
        super().__init__(config)
        self._store: RbacStore | None = None

    @property
    def store(self) -> RbacStore:
        if self._store is None:
            engine = self.context.get_memory_engine()
            self._store = RbacStore(engine._get_pool)  # type: ignore[attr-defined]
        return self._store

    async def _require(
        self, bank_id: str, request_context: RequestContext, needed: Capability | None, what: str
    ) -> ValidationResult:
        try:
            caller = await resolve_caller(self.store, request_context)
        except CallerError as e:
            return ValidationResult.reject(e.reason, e.status_code)
        if caller == _SYSTEM:
            return ValidationResult.accept()
        if caller is ANONYMOUS:
            headers = request_context.extra_headers or {}
            logger.warning(
                "rbac.anonymous op=%s bank=%s ip=%s ua=%s",
                what,
                bank_id,
                headers.get("x-forwarded-for", "-"),
                headers.get("user-agent", "-"),
            )
        if needed is None:
            # An operation upstream added after this map was written: refuse until classified.
            logger.error("rbac: unclassified operation %s on bank %s refused", what, bank_id)
            return ValidationResult.reject(f"Operation '{what}' is not permitted", 403)
        if await self._unborn(bank_id):
            # Core validates a write before auto-creating its bank; the creation itself is
            # checked (and ownership recorded) by validate_create_bank, which runs next.
            return ValidationResult.accept()
        caps = await bank_capabilities(self.store, caller, bank_id)  # type: ignore[arg-type]
        return denial(bank_id, caps, needed, what) or ValidationResult.accept()

    async def _unborn(self, bank_id: str) -> bool:
        """No ACL row and no bank row: the bank does not exist yet. (A bank row without an
        ACL row is a pre-RBAC leftover and stays admin-only.)"""
        return await self.store.get_acl(bank_id) is None and not await self.store.bank_exists(bank_id)

    # ---------------------------------------------------------------- core operations

    async def validate_retain(self, ctx: RetainContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.WRITE, "retain")

    async def validate_recall(self, ctx: RecallContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.READ, "recall")

    async def validate_reflect(self, ctx: ReflectContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.READ, "reflect")

    async def validate_consolidate(self, ctx: ConsolidateContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.WRITE, "consolidate")

    async def validate_mental_model_get(self, ctx: MentalModelGetContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.READ, "read mental models")

    async def validate_mental_model_refresh(self, ctx: MentalModelRefreshContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.WRITE, "refresh mental models")

    async def validate_memory_update(self, ctx: MemoryUpdateContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.WRITE, "update memories")

    async def validate_import(self, ctx: ImportContext) -> ValidationResult:
        return await self._require(ctx.bank_id, ctx.request_context, Capability.WRITE, "import")

    async def validate_bank_read(self, ctx: BankReadContext) -> ValidationResult:
        needed = READ_OP_CAPABILITY.get(ctx.operation)
        return await self._require(ctx.bank_id, ctx.request_context, needed, str(ctx.operation))

    async def validate_bank_write(self, ctx: BankWriteContext) -> ValidationResult:
        needed = WRITE_OP_CAPABILITY.get(ctx.operation)
        return await self._require(ctx.bank_id, ctx.request_context, needed, str(ctx.operation))

    # ---------------------------------------------------------------- banks

    async def validate_create_bank(self, ctx: CreateBankContext) -> ValidationResult:
        """Record the creator as owner of a new (public) bank; first writer wins on races."""
        try:
            caller = await resolve_caller(self.store, ctx.request_context)
        except CallerError as e:
            return ValidationResult.reject(e.reason, e.status_code)
        if caller != _SYSTEM and await self.store.get_acl(ctx.bank_id) is not None:
            # Already claimed (a racing create, or a bank whose row is not there yet).
            caps = await bank_capabilities(self.store, caller, ctx.bank_id)  # type: ignore[arg-type]
            return denial(ctx.bank_id, caps, Capability.WRITE, "create the bank") or ValidationResult.accept()
        owner = None if caller == _SYSTEM or caller is ANONYMOUS else caller.id  # type: ignore[union-attr]
        await self.store.record_new_bank(ctx.bank_id, owner_id=owner)
        return ValidationResult.accept()

    async def bank_list_scope(self, request_context: RequestContext) -> BankListScope | None:
        try:
            caller = await resolve_caller(self.store, request_context)
        except CallerError:
            return BankListScope(bank_ids=[])
        if caller == _SYSTEM or caller.is_admin:  # type: ignore[union-attr]
            return BankListScope(bank_ids=None)
        return BankListScope(bank_ids=await self.store.readable_bank_ids(caller.id))  # type: ignore[union-attr]

    async def filter_mcp_tools(
        self, bank_id: str, request_context: RequestContext, tools: frozenset[str]
    ) -> frozenset[str]:
        caller = await resolve_caller(self.store, request_context)
        if caller == _SYSTEM:
            return tools
        if await self.store.get_acl(bank_id) is None and not caller.is_admin:  # type: ignore[union-attr]
            # Unknown session bank (e.g. multi-bank /mcp before the bank exists): every call is
            # still checked against its own bank, so do not hide anything here.
            return tools
        caps = await bank_capabilities(self.store, caller, bank_id)  # type: ignore[arg-type]
        if Capability.READ not in caps:
            return tools & _BANK_AGNOSTIC_TOOLS
        return frozenset(t for t in tools if t in _BANK_AGNOSTIC_TOOLS or MCP_TOOL_CAPABILITY.get(t) in caps)
