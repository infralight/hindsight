"""RbacOperationValidator through the real HTTP surface: who can do what on which bank."""

import asyncio
import logging

from rbac_helpers import make_user, recall, retain, unique_bank

from hindsight_api import RequestContext


async def _private_bank(api, store, owner_headers) -> str:
    bank = unique_bank()
    assert await retain(api, bank, owner_headers) == 200
    await store.set_visibility(bank, "private")
    return bank


async def test_new_bank_is_public_and_owned_by_creator(rbac_on, rbac_store, api):
    alice, a = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    acl = await rbac_store.get_acl(bank)
    assert acl.visibility == "public" and acl.owner_id == alice.id


async def test_private_bank_is_404_for_stranger(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)

    assert await recall(api, bank, b) == 404
    assert (await api.get(f"/v1/default/banks/{bank}/documents", headers=b)).status_code == 404
    assert (await api.get(f"/v1/default/banks/{bank}/memories/list", headers=b)).status_code == 404
    assert await retain(api, bank, b) == 404  # no re-creation of someone else's private bank
    assert await recall(api, bank, a) == 200


async def test_public_bank_writer_for_everyone(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    assert await retain(api, bank, b, "Bob likes spaces.") == 200
    assert await recall(api, bank, b) == 200
    assert (await api.delete(f"/v1/default/banks/{bank}", headers=b)).status_code == 403


async def test_owner_deletes_private_not_public(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    assert (await api.delete(f"/v1/default/banks/{bank}", headers=a)).status_code == 403
    await rbac_store.set_visibility(bank, "private")
    assert (await api.delete(f"/v1/default/banks/{bank}", headers=a)).status_code == 200
    assert await rbac_store.get_acl(bank) is None  # swept with the bank


async def test_admin_deletes_public(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, root = await make_user(rbac_store, admin=True)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    assert (await api.delete(f"/v1/default/banks/{bank}", headers=root)).status_code == 200


async def test_reader_grant_cannot_retain(rbac_on, rbac_store, api):
    from hindsight_ext_rbac.policy import Role

    _, a = await make_user(rbac_store)
    bob, b = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)
    await rbac_store.put_grant(bank, "principal", bob.id, Role.READER)
    assert await recall(api, bank, b) == 200
    assert await retain(api, bank, b) == 403


async def test_team_grant_gives_writer(rbac_on, rbac_store, api):
    from hindsight_ext_rbac.policy import Role

    _, a = await make_user(rbac_store)
    bob, b = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)
    team = await rbac_store.create_team(f"team-{bank}")
    await rbac_store.add_member(team.id, bob.id)
    await rbac_store.put_grant(bank, "team", team.id, Role.WRITER)
    assert await retain(api, bank, b) == 200
    assert (await api.delete(f"/v1/default/banks/{bank}", headers=b)).status_code == 403


async def test_bank_list_shows_only_readable(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    public = unique_bank()
    assert await retain(api, public, a) == 200
    private = await _private_bank(api, rbac_store, a)

    def ids(response) -> set[str]:
        assert response.status_code == 200
        return {bank["bank_id"] for bank in response.json()["banks"]}

    bob_sees = ids(await api.get("/v1/default/banks?limit=1000", headers=b))
    assert public in bob_sees and private not in bob_sees
    assert {public, private} <= ids(await api.get("/v1/default/banks?limit=1000", headers=a))


async def test_alias_cannot_bypass(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)
    alias = f"{bank}-alias"
    response = await api.post(f"/v1/default/banks/{bank}/aliases", json={"alias": alias}, headers=a)
    assert response.status_code in (200, 201), response.text
    assert await recall(api, alias, a) == 200
    assert await recall(api, alias, b) == 404


async def test_clone_and_export_private_bank_by_stranger(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)
    target = unique_bank()
    clone = await api.post(f"/v1/default/banks/{bank}/clone", params={"target_bank_id": target}, headers=b)
    assert clone.status_code == 404
    assert await rbac_store.get_acl(target) is None
    assert (await api.post(f"/v1/default/banks/{bank}/transfer/export", headers=b)).status_code == 404


async def test_concurrent_first_create_single_owner(rbac_on, rbac_store, api):
    alice, a = await make_user(rbac_store)
    bob, b = await make_user(rbac_store)
    bank = unique_bank()
    results = await asyncio.gather(retain(api, bank, a, "from alice"), retain(api, bank, b, "from bob"))
    assert results == [200, 200]
    acl = await rbac_store.get_acl(bank)
    assert acl.visibility == "public" and acl.owner_id in {alice.id, bob.id}


async def test_chunk_route_is_404_for_stranger(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)
    docs = (await api.get(f"/v1/default/banks/{bank}/documents", headers=a)).json()["items"]
    chunks = (await api.get(f"/v1/default/banks/{bank}/documents/{docs[0]['id']}/chunks", headers=a)).json()
    chunk_id = (chunks.get("items") or chunks.get("chunks"))[0]["chunk_id"]
    assert (await api.get(f"/v1/default/chunks/{chunk_id}", headers=a)).status_code == 200
    assert (await api.get(f"/v1/default/chunks/{chunk_id}", headers=b)).status_code == 404


async def test_webhooks_need_manage(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    body = {"url": "https://example.com/hook"}
    assert (await api.post(f"/v1/default/banks/{bank}/webhooks", json=body, headers=b)).status_code == 403
    assert (await api.get(f"/v1/default/banks/{bank}/webhooks", headers=b)).status_code == 403
    assert (await api.get(f"/v1/default/banks/{bank}/webhooks", headers=a)).status_code == 200


async def test_bank_without_acl_is_admin_only(rbac_on, rbac_store, rbac_memory, api):
    _, b = await make_user(rbac_store)
    _, root = await make_user(rbac_store, admin=True)
    bank = unique_bank()
    # A bank that slipped past the migration's backfill: no ACL row.
    await rbac_memory.ensure_bank_profile(bank_id=bank, request_context=RequestContext(internal=True))
    assert await rbac_store.get_acl(bank) is not None  # system create records it ...
    pool = await rbac_memory._get_pool()
    await pool.execute("DELETE FROM rbac_bank_acl WHERE bank_id = $1", bank)  # ... so drop it
    assert await recall(api, bank, b) == 404
    assert await recall(api, bank, root) == 200


async def test_worker_rechecks_after_revoke(rbac_on, rbac_store, rbac_memory, api, monkeypatch):
    bob, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, b) == 200

    captured: list[dict] = []

    async def capture(task_dict: dict) -> None:
        captured.append(task_dict)

    monkeypatch.setattr(rbac_memory._task_backend, "submit_task", capture)
    response = await api.post(
        f"/v1/default/banks/{bank}/memories", json={"items": [{"content": "later"}], "async": True}, headers=b
    )
    assert response.status_code == 200 and captured
    assert captured[0].get("_tenant_id") == bob.id

    await rbac_store.set_disabled(bob.id, True)
    executed: list[str] = []
    real_validate = rbac_on.validate_retain

    async def spy(ctx):
        result = await real_validate(ctx)
        executed.append("allowed" if result.allowed else f"refused:{result.status_code}")
        return result

    monkeypatch.setattr(rbac_on, "validate_retain", spy)
    await rbac_memory.execute_task(captured[0])
    assert executed and executed[-1] == "refused:401"


async def test_anonymous_ops_are_logged(install_tenant, install_validator, api, caplog):
    install_tenant(auth_mode="optional")
    install_validator()
    bank = unique_bank()
    headers = {"User-Agent": "legacy-agent/1.0", "X-Forwarded-For": "10.1.2.3"}
    with caplog.at_level(logging.WARNING, logger="hindsight_ext_rbac.validator"):
        assert await retain(api, bank, headers) == 200
    assert any("rbac.anonymous" in r.getMessage() and bank in r.getMessage() for r in caplog.records)


async def test_system_context_is_allowed(rbac_on, rbac_store, api):
    from hindsight_api.extensions import BankReadContext, BankReadOperation

    _, a = await make_user(rbac_store)
    bank = await _private_bank(api, rbac_store, a)
    result = await rbac_on.validate_bank_read(
        BankReadContext(
            bank_id=bank, operation=BankReadOperation.LIST_DOCUMENTS, request_context=RequestContext(internal=True)
        )
    )
    assert result.allowed


async def test_mcp_tools_follow_role(rbac_on, rbac_store, api):
    from hindsight_api.mcp_tools import _ALL_TOOLS

    alice, a = await make_user(rbac_store)
    bob, _ = await make_user(rbac_store)
    public = unique_bank()
    assert await retain(api, public, a) == 200
    private = await _private_bank(api, rbac_store, a)

    def ctx(principal) -> RequestContext:
        return RequestContext(tenant_id=principal.id)

    owner_tools = await rbac_on.filter_mcp_tools(private, ctx(alice), _ALL_TOOLS)
    assert "delete_bank" in owner_tools and "retain" in owner_tools

    public_tools = await rbac_on.filter_mcp_tools(public, ctx(bob), _ALL_TOOLS)
    assert "retain" in public_tools and "delete_bank" not in public_tools

    assert await rbac_on.filter_mcp_tools(private, ctx(bob), _ALL_TOOLS) == frozenset({"list_banks", "create_bank"})
    assert await rbac_on.filter_mcp_tools(unique_bank(), ctx(bob), _ALL_TOOLS) == _ALL_TOOLS
