"""RbacStore against a real database: tokens, disablement, teams, bank access."""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest


def _email() -> str:
    return f"u-{uuid.uuid4().hex[:10]}@x.io"


def _bank() -> str:
    return f"rbac-store-{uuid.uuid4().hex[:10]}"


@pytest.fixture
def store(rbac_memory):
    from hindsight_ext_rbac.store import RbacStore

    return RbacStore(rbac_memory._get_pool)


async def _user(store, *, admin: bool = False):
    principal = await store.upsert_oidc_user(_email(), "Test User", is_bootstrap_admin=admin)
    assert principal is not None
    return principal


async def test_token_roundtrip(store):
    alice = await _user(store)
    new = await store.create_token(alice.id, "laptop", expires_at=None)
    assert new.token.startswith("hsp_") and new.prefix == new.token[:12]

    found = await store.principal_by_token_hash(hashlib.sha256(new.token.encode()).hexdigest())
    assert found is not None
    principal, token_id = found
    assert principal.id == alice.id and token_id == new.id

    assert await store.revoke_token(new.id, alice.id) is True
    assert await store.principal_by_token_hash(hashlib.sha256(new.token.encode()).hexdigest()) is None


async def test_expired_token_is_dead(store):
    alice = await _user(store)
    new = await store.create_token(alice.id, "old", expires_at=datetime.now(UTC) - timedelta(minutes=1))
    assert await store.principal_by_token_hash(hashlib.sha256(new.token.encode()).hexdigest()) is None


async def test_other_principal_cannot_revoke_my_token(store):
    alice, bob = await _user(store), await _user(store)
    new = await store.create_token(alice.id, "laptop", expires_at=None)
    assert await store.revoke_token(new.id, bob.id) is False
    assert await store.revoke_token(new.id, None) is True  # admin path


async def test_disabled_principal_tokens_dead(store):
    alice = await _user(store)
    new = await store.create_token(alice.id, "laptop", expires_at=None)
    await store.set_disabled(alice.id, True)
    assert await store.principal_by_token_hash(hashlib.sha256(new.token.encode()).hexdigest()) is None
    assert await store.get_principal(alice.id) is None
    assert await store.upsert_oidc_user(alice.email, "Alice", is_bootstrap_admin=False) is None


async def test_team_grant_resolves(store):
    from hindsight_ext_rbac.policy import Role

    alice = await _user(store)
    team = await store.create_team(f"team-{uuid.uuid4().hex[:8]}")
    bank = _bank()
    await store.record_new_bank(bank, owner_id=None)
    await store.put_grant(bank, "team", team.id, Role.READER)
    assert await store.grant_roles(bank, alice.id) == []

    await store.add_member(team.id, alice.id)
    assert await store.grant_roles(bank, alice.id) == [Role.READER]

    await store.remove_member(team.id, alice.id)
    assert await store.grant_roles(bank, alice.id) == []


async def test_record_new_bank_first_writer_wins(store):
    alice, bob = await _user(store), await _user(store)
    bank = _bank()
    await store.record_new_bank(bank, owner_id=alice.id)
    await store.record_new_bank(bank, owner_id=bob.id)
    acl = await store.get_acl(bank)
    assert acl is not None
    assert acl.owner_id == alice.id and acl.visibility == "public"


async def test_readable_bank_ids(store):
    from hindsight_ext_rbac.policy import Role

    alice, bob = await _user(store), await _user(store)
    team = await store.create_team(f"team-{uuid.uuid4().hex[:8]}")
    await store.add_member(team.id, bob.id)

    public, owned, via_team, hidden = _bank(), _bank(), _bank(), _bank()
    await store.record_new_bank(public, owner_id=alice.id)
    for bank in (owned, via_team, hidden):
        await store.record_new_bank(bank, owner_id=alice.id)
        await store.set_visibility(bank, "private")
    await store.put_grant(via_team, "team", team.id, Role.READER)

    bob_sees = set(await store.readable_bank_ids(bob.id))
    assert public in bob_sees and via_team in bob_sees
    assert owned not in bob_sees and hidden not in bob_sees

    alice_sees = set(await store.readable_bank_ids(alice.id))
    assert {public, owned, via_team, hidden} <= alice_sees

    anonymous_sees = set(await store.readable_bank_ids("anonymous"))
    assert public in anonymous_sees and via_team not in anonymous_sees


async def test_bootstrap_admin_upsert(store):
    email = _email()
    first = await store.upsert_oidc_user(email, "Root", is_bootstrap_admin=True)
    assert first is not None and first.is_admin
    again = await store.upsert_oidc_user(email.upper(), "Root", is_bootstrap_admin=False)
    assert again is not None and again.id == first.id and again.is_admin  # never cleared by login


async def test_service_account_cannot_be_admin(store):
    svc = await store.create_service_account("heimdall")
    assert svc.kind == "service" and svc.email is None
    with pytest.raises(ValueError):
        await store.set_admin(svc.id, True)


async def test_grants_listing_and_delete(store):
    from hindsight_ext_rbac.policy import Role

    alice = await _user(store)
    bank = _bank()
    await store.record_new_bank(bank, owner_id=None)
    await store.put_grant(bank, "principal", alice.id, Role.READER)
    await store.put_grant(bank, "principal", alice.id, Role.WRITER)  # upsert
    grants = await store.list_grants(bank)
    assert [(g.principal_type, g.principal_id, g.role, g.name) for g in grants] == [
        ("principal", alice.id, Role.WRITER, "Test User")
    ]
    assert await store.delete_grant(bank, "principal", alice.id) is True
    assert await store.list_grants(bank) == []
