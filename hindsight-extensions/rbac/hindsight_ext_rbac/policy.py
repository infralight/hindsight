"""Who may do what on a bank: roles, capabilities, and what each operation needs.

Pure data and functions — no I/O — so the whole access model is testable without a
database. The operation maps are explicit: an operation upstream adds later is absent
until someone decides what it needs, and the validator refuses absent operations.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from hindsight_api.extensions.operation_validator import BankReadOperation, BankWriteOperation


class Capability(StrEnum):
    READ = "read"
    WRITE = "write"
    MANAGE = "manage"
    DELETE_BANK = "delete_bank"


class Role(StrEnum):
    READER = "reader"
    WRITER = "writer"
    OWNER = "owner"


ROLE_RANK: dict[Role, int] = {Role.READER: 1, Role.WRITER: 2, Role.OWNER: 3}

_ROLE_CAPABILITIES: dict[Role, frozenset[Capability]] = {
    Role.READER: frozenset({Capability.READ}),
    Role.WRITER: frozenset({Capability.READ, Capability.WRITE}),
    Role.OWNER: frozenset({Capability.READ, Capability.WRITE, Capability.MANAGE}),
}

ALL_CAPABILITIES: frozenset[Capability] = frozenset(Capability)


@dataclass(frozen=True)
class Principal:
    """An authenticated caller: a user, a service account, or the anonymous caller."""

    id: str
    kind: Literal["user", "service", "anonymous"]
    is_admin: bool
    email: str | None
    name: str


ANONYMOUS = Principal(id="anonymous", kind="anonymous", is_admin=False, email=None, name="anonymous")


@dataclass(frozen=True)
class BankAcl:
    bank_id: str
    visibility: Literal["private", "public"]
    owner_id: str | None


def effective_role(principal: Principal, acl: BankAcl | None, grant_roles: Iterable[Role]) -> Role | None:
    """The highest role the principal holds on the bank, or None for no access.

    A bank with no ACL row is private with no owner: only admins reach it.
    """
    if principal.is_admin:
        return Role.OWNER
    if acl is None:
        return None
    candidates = list(grant_roles)
    if acl.owner_id is not None and acl.owner_id == principal.id:
        candidates.append(Role.OWNER)
    if acl.visibility == "public":
        candidates.append(Role.WRITER)
    return max(candidates, key=ROLE_RANK.__getitem__, default=None)


def capabilities(principal: Principal, acl: BankAcl | None, role: Role | None) -> frozenset[Capability]:
    """What the principal may do on the bank, given its effective role."""
    if principal.is_admin:
        return ALL_CAPABILITIES
    if role is None:
        return frozenset()
    caps = _ROLE_CAPABILITIES[role]
    # Public banks are shared knowledge: only an admin may delete one.
    if role is Role.OWNER and acl is not None and acl.visibility == "private":
        caps = caps | {Capability.DELETE_BANK}
    return caps


_R, _W, _M, _D = Capability.READ, Capability.WRITE, Capability.MANAGE, Capability.DELETE_BANK

READ_OP_CAPABILITY: dict[BankReadOperation, Capability] = {
    BankReadOperation.EXPORT_KNOWLEDGE_BASE: _R,
    BankReadOperation.GET_BANK_CONFIG: _R,
    BankReadOperation.GET_BANK_PROFILE: _R,
    BankReadOperation.GET_BANK_STATS: _R,
    BankReadOperation.GET_CHUNK: _R,
    BankReadOperation.GET_DIRECTIVE: _R,
    BankReadOperation.GET_DOCUMENT: _R,
    BankReadOperation.GET_DOCUMENT_HISTORY: _R,
    BankReadOperation.GET_ENTITY: _R,
    BankReadOperation.GET_ENTITY_GRAPH: _R,
    BankReadOperation.GET_ENTITY_STATE: _R,
    BankReadOperation.GET_GRAPH_DATA: _R,
    BankReadOperation.GET_KNOWLEDGE_BASE_TREE: _R,
    BankReadOperation.GET_KNOWLEDGE_PAGE: _R,
    BankReadOperation.GET_MEMORIES_TIMESERIES: _R,
    BankReadOperation.GET_MEMORY_UNIT: _R,
    BankReadOperation.GET_MENTAL_MODEL_HISTORY: _R,
    BankReadOperation.GET_OBSERVATION_HISTORY: _R,
    BankReadOperation.GET_OPERATION_STATUS: _R,
    BankReadOperation.LIST_AUDIT_LOGS: _M,
    BankReadOperation.LIST_BANK_ALIASES: _R,
    BankReadOperation.LIST_DIRECTIVES: _R,
    BankReadOperation.LIST_DOCUMENT_CHUNKS: _R,
    BankReadOperation.LIST_DOCUMENTS: _R,
    BankReadOperation.LIST_ENTITIES: _R,
    BankReadOperation.LIST_MEMORY_UNITS: _R,
    BankReadOperation.LIST_MENTAL_MODEL_TAGS: _R,
    BankReadOperation.LIST_MENTAL_MODELS: _R,
    BankReadOperation.LIST_OBSERVATION_SCOPES: _R,
    BankReadOperation.LIST_OPERATIONS: _R,
    BankReadOperation.LIST_TAGS: _R,
    # Webhook targets can embed credentials and say where bank data is sent.
    BankReadOperation.LIST_WEBHOOK_DELIVERIES: _M,
    BankReadOperation.LIST_WEBHOOKS: _M,
    BankReadOperation.SEARCH_KNOWLEDGE_BASE: _R,
}

WRITE_OP_CAPABILITY: dict[BankWriteOperation, Capability] = {
    BankWriteOperation.CANCEL_OPERATION: _W,
    BankWriteOperation.CLEAR_MENTAL_MODEL: _W,
    BankWriteOperation.CLEAR_OBSERVATIONS: _W,
    BankWriteOperation.CLEAR_OBSERVATIONS_FOR_MEMORY: _W,
    BankWriteOperation.CREATE_BANK_ALIAS: _W,
    BankWriteOperation.CREATE_DIRECTIVE: _W,
    BankWriteOperation.CREATE_KNOWLEDGE_FOLDER: _W,
    BankWriteOperation.CREATE_KNOWLEDGE_PAGE: _W,
    BankWriteOperation.CREATE_MENTAL_MODEL: _W,
    BankWriteOperation.CREATE_WEBHOOK: _M,
    BankWriteOperation.DELETE_BANK: _D,
    BankWriteOperation.DELETE_BANK_ALIAS: _W,
    BankWriteOperation.DELETE_DIRECTIVE: _W,
    BankWriteOperation.DELETE_DOCUMENT: _W,
    BankWriteOperation.DELETE_KNOWLEDGE_NODE: _W,
    BankWriteOperation.DELETE_MENTAL_MODEL: _W,
    BankWriteOperation.DELETE_OPERATION: _W,
    BankWriteOperation.DELETE_WEBHOOK: _M,
    BankWriteOperation.IMPORT_DOCUMENTS: _W,
    BankWriteOperation.MOVE_KNOWLEDGE_NODE: _W,
    BankWriteOperation.RENAME_KNOWLEDGE_NODE: _W,
    BankWriteOperation.REPROCESS_DOCUMENT: _W,
    BankWriteOperation.RESET_BANK_CONFIG: _W,
    BankWriteOperation.RETRY_FAILED_CONSOLIDATION: _W,
    BankWriteOperation.RETRY_OPERATION: _W,
    BankWriteOperation.RUN_CONSOLIDATION: _W,
    BankWriteOperation.SET_BANK_MISSION: _W,
    BankWriteOperation.SUBMIT_ASYNC_CONSOLIDATION: _W,
    BankWriteOperation.SUBMIT_ASYNC_GRAPH_MAINTENANCE: _W,
    BankWriteOperation.SUBMIT_ASYNC_VECTOR_INDEX_MAINTENANCE: _W,
    BankWriteOperation.UPDATE_BANK: _W,
    BankWriteOperation.UPDATE_BANK_CONFIG: _W,
    BankWriteOperation.UPDATE_BANK_DISPOSITION: _W,
    BankWriteOperation.UPDATE_DIRECTIVE: _W,
    BankWriteOperation.UPDATE_DOCUMENT: _W,
    BankWriteOperation.UPDATE_KNOWLEDGE_PAGE: _W,
    BankWriteOperation.UPDATE_MEMORY_UNIT: _W,
    BankWriteOperation.UPDATE_MENTAL_MODEL: _W,
    BankWriteOperation.UPDATE_WEBHOOK: _M,
}

_READ_TOOLS = (
    "recall",
    "reflect",
    "list_banks",
    "list_mental_models",
    "get_mental_model",
    "list_directives",
    "list_memories",
    "get_memory",
    "list_documents",
    "get_document",
    "list_operations",
    "get_operation",
    "list_tags",
    "get_bank",
    "get_bank_stats",
    "get_knowledge_base_tree",
    "search_knowledge_base",
    "get_knowledge_page",
)
_WRITE_TOOLS = (
    "retain",
    "sync_retain",
    "create_bank",
    "create_mental_model",
    "update_mental_model",
    "delete_mental_model",
    "refresh_mental_model",
    "clear_mental_model",
    "create_directive",
    "delete_directive",
    "update_memory",
    "invalidate_memory",
    "delete_document",
    "cancel_operation",
    "update_bank",
    "clear_memories",
    "create_knowledge_folder",
    "create_knowledge_page",
    "update_knowledge_node",
    "delete_knowledge_node",
)

MCP_TOOL_CAPABILITY: dict[str, Capability] = {
    **dict.fromkeys(_READ_TOOLS, _R),
    **dict.fromkeys(_WRITE_TOOLS, _W),
    "delete_bank": _D,
}
