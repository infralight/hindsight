"""Fork core patches: audit actor on every entry, audit-log reads (and history
exports/clones) gated as manage, MCP tool filtering failing closed."""

import uuid
from dataclasses import replace

from rbac_helpers import make_user, retain, unique_bank

from hindsight_api import RequestContext


def _audit_on(memory) -> None:
    resolver = memory._config_resolver
    resolver._global_config = replace(resolver._global_config, audit_log_enabled=True)
    memory._audit_logger._enabled = True


async def test_audit_log_read_needs_manage(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200  # public, owned by alice
    for path in ("audit-logs", "audit-logs/stats"):
        assert (await api.get(f"/v1/default/banks/{bank}/{path}", headers=b)).status_code == 403, path
        assert (await api.get(f"/v1/default/banks/{bank}/{path}", headers=a)).status_code == 200, path
    entry = f"/v1/default/banks/{bank}/audit-logs/{uuid.uuid4()}"
    assert (await api.get(entry, headers=b)).status_code == 403


async def test_history_export_and_clone_need_manage(rbac_on, rbac_store, api):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    export = f"/v1/default/banks/{bank}/transfer/export"
    assert (await api.post(export, params={"include_history": "true"}, headers=b)).status_code == 403
    assert (await api.post(export, params={"include_history": "false"}, headers=b)).status_code == 202
    clone = f"/v1/default/banks/{bank}/clone"
    params = {"target_bank_id": unique_bank(), "include_history": "true"}
    assert (await api.post(clone, params=params, headers=b)).status_code == 403


async def test_audit_entries_record_the_actor(rbac_on, rbac_store, rbac_memory, api):
    _audit_on(rbac_memory)
    alice, a = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(api, bank, a) == 200
    response = await api.post(
        f"/v1/default/banks/{bank}/memories", json={"items": [{"content": "later"}], "async": True}, headers=a
    )
    assert response.status_code == 200
    await rbac_memory._audit_logger.drain()
    pool = await rbac_memory._get_pool()
    rows = await pool.fetch("SELECT transport, metadata FROM audit_log WHERE bank_id = $1", bank)
    assert {r["transport"] for r in rows} >= {"http", "system"}
    assert all(alice.id in r["metadata"] for r in rows), [r["metadata"] for r in rows]


def test_audit_actor():
    from hindsight_api.engine.audit import audit_actor

    assert audit_actor(RequestContext(tenant_id="p-1")) == "p-1"
    assert audit_actor(RequestContext(internal=True)) == "system"
    assert audit_actor(RequestContext()) == "anonymous"
    assert audit_actor(None) == "system"
