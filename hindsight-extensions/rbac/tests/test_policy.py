"""Bank roles and the capability each engine operation and MCP tool needs.

The maps are explicit on purpose: an operation upstream adds later must fail the
completeness tests here (and be refused by the validator) until someone decides
what it needs, rather than silently defaulting to some capability.
"""

import pytest
from hindsight_api.extensions.operation_validator import BankReadOperation, BankWriteOperation
from hindsight_api.mcp_tools import _ALL_TOOLS

from hindsight_ext_rbac.policy import (
    ANONYMOUS,
    MCP_TOOL_CAPABILITY,
    READ_OP_CAPABILITY,
    WRITE_OP_CAPABILITY,
    BankAcl,
    Capability,
    Principal,
    Role,
    capabilities,
    effective_role,
)

R, W, M, D = Capability.READ, Capability.WRITE, Capability.MANAGE, Capability.DELETE_BANK

ALICE = Principal(id="alice", kind="user", is_admin=False, email="alice@x.io", name="Alice")
BOB = Principal(id="bob", kind="user", is_admin=False, email="bob@x.io", name="Bob")
ADMIN = Principal(id="root", kind="user", is_admin=True, email="root@x.io", name="Root")


def _acl(visibility: str, owner: str | None = "alice") -> BankAcl:
    return BankAcl(bank_id="b", visibility=visibility, owner_id=owner)  # type: ignore[arg-type]


def _caps(principal: Principal, acl: BankAcl | None, grants: list[Role] = []) -> frozenset[Capability]:  # noqa: B006
    return capabilities(principal, acl, effective_role(principal, acl, grants))


def test_every_read_operation_is_mapped():
    assert set(READ_OP_CAPABILITY) == set(BankReadOperation)


def test_every_write_operation_is_mapped():
    assert set(WRITE_OP_CAPABILITY) == set(BankWriteOperation)


def test_every_mcp_tool_is_mapped():
    assert set(MCP_TOOL_CAPABILITY) == set(_ALL_TOOLS)


def test_sensitive_operations_need_more_than_write():
    assert READ_OP_CAPABILITY[BankReadOperation.LIST_WEBHOOKS] is M
    assert READ_OP_CAPABILITY[BankReadOperation.LIST_WEBHOOK_DELIVERIES] is M
    assert READ_OP_CAPABILITY[BankReadOperation.LIST_AUDIT_LOGS] is M
    assert WRITE_OP_CAPABILITY[BankWriteOperation.CREATE_WEBHOOK] is M
    assert WRITE_OP_CAPABILITY[BankWriteOperation.DELETE_BANK] is D
    assert MCP_TOOL_CAPABILITY["delete_bank"] is D
    assert MCP_TOOL_CAPABILITY["recall"] is R
    assert MCP_TOOL_CAPABILITY["retain"] is W


@pytest.mark.parametrize(
    ("principal", "acl", "grants", "expected"),
    [
        pytest.param(BOB, _acl("public"), [], {R, W}, id="public-stranger"),
        pytest.param(BOB, _acl("private"), [], set(), id="private-stranger"),
        pytest.param(ALICE, _acl("private"), [], {R, W, M, D}, id="private-owner"),
        pytest.param(ALICE, _acl("public"), [], {R, W, M}, id="public-owner"),
        pytest.param(ADMIN, _acl("public"), [], {R, W, M, D}, id="admin-public"),
        pytest.param(ADMIN, None, [], {R, W, M, D}, id="admin-no-acl"),
        pytest.param(BOB, _acl("private"), [Role.READER], {R}, id="private-reader"),
        pytest.param(BOB, _acl("private"), [Role.WRITER], {R, W}, id="private-writer"),
        pytest.param(BOB, _acl("private"), [Role.READER, Role.OWNER], {R, W, M, D}, id="private-co-owner"),
        pytest.param(BOB, _acl("public"), [Role.READER], {R, W}, id="public-beats-reader-grant"),
        pytest.param(ANONYMOUS, _acl("public", owner=None), [], {R, W}, id="anonymous-public"),
        pytest.param(ANONYMOUS, _acl("private", owner=None), [], set(), id="anonymous-private"),
    ],
)
def test_role_matrix(principal, acl, grants, expected):
    assert _caps(principal, acl, grants) == frozenset(expected)


def test_missing_acl_is_private_with_no_owner():
    assert effective_role(ALICE, None, []) is None
    assert _caps(ALICE, None) == frozenset()


def test_grants_on_missing_acl_do_not_open_the_bank():
    # Grants without an ACL row can only come from a half-deleted bank: still closed.
    assert effective_role(BOB, None, [Role.WRITER]) is None
