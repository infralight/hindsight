"""/ext/rbac management API: tokens, principals, service accounts, teams, bank sharing."""

import httpx
import pytest_asyncio
from rbac_helpers import make_user, recall, retain, unique_bank


@pytest_asyncio.fixture
async def ext(rbac_memory, rbac_on, pg0_db_url):
    from hindsight_api.api.http import create_app
    from hindsight_api.extensions.context import DefaultExtensionContext
    from hindsight_ext_rbac import RbacHttpExtension

    http_ext = RbacHttpExtension({})
    http_ext.set_context(DefaultExtensionContext(database_url=pg0_db_url, memory_engine=rbac_memory))
    app = create_app(rbac_memory, initialize_memory=False, http_extension=http_ext)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client


async def test_me(ext, rbac_store):
    alice, a = await make_user(rbac_store)
    body = (await ext.get("/ext/rbac/me", headers=a)).json()
    assert body == {"id": alice.id, "kind": "user", "email": alice.email, "name": "Test User", "is_admin": False}
    assert (await ext.get("/ext/rbac/me")).status_code == 401


async def test_anonymous_is_401_even_in_optional_mode(ext, install_tenant):
    install_tenant(auth_mode="optional")
    assert (await ext.get("/ext/rbac/me")).status_code == 401
    assert (await ext.get("/ext/rbac/teams")).status_code == 401


async def test_directory(ext, rbac_store):
    alice, a = await make_user(rbac_store)
    team = await rbac_store.create_team(f"dir-team-{alice.id[:8]}")
    body = (await ext.get("/ext/rbac/directory", params={"q": alice.email[:8]}, headers=a)).json()
    assert alice.id in {p["id"] for p in body["principals"]}
    body = (await ext.get("/ext/rbac/directory", params={"q": "dir-team"}, headers=a)).json()
    assert team.id in {t["id"] for t in body["teams"]}


async def test_tokens_lifecycle(ext, rbac_store):
    _, a = await make_user(rbac_store)
    _, b = await make_user(rbac_store)
    _, root = await make_user(rbac_store, admin=True)

    created = await ext.post("/ext/rbac/tokens", json={"name": "laptop"}, headers=a)
    assert created.status_code == 201
    token = created.json()
    assert token["token"].startswith("hsp_") and token["name"] == "laptop"
    new_headers = {"Authorization": f"Bearer {token['token']}"}
    assert (await ext.get("/ext/rbac/me", headers=new_headers)).status_code == 200

    listed = (await ext.get("/ext/rbac/tokens", headers=a)).json()
    assert token["id"] in {t["id"] for t in listed["tokens"]}
    assert all("token" not in t for t in listed["tokens"])  # shown once only

    assert (await ext.delete(f"/ext/rbac/tokens/{token['id']}", headers=b)).status_code == 404
    assert (await ext.delete(f"/ext/rbac/tokens/{token['id']}", headers=a)).status_code == 204
    assert (await ext.get("/ext/rbac/me", headers=new_headers)).status_code == 401

    other = (await ext.post("/ext/rbac/tokens", json={"name": "x"}, headers=b)).json()
    assert (await ext.delete(f"/ext/rbac/tokens/{other['id']}", headers=root)).status_code == 204


async def test_principals_admin_only(ext, rbac_store):
    bob, b = await make_user(rbac_store)
    _, root = await make_user(rbac_store, admin=True)
    assert (await ext.get("/ext/rbac/principals", headers=b)).status_code == 403
    listed = (await ext.get("/ext/rbac/principals", headers=root)).json()["principals"]
    assert bob.id in {p["id"] for p in listed}

    assert (await ext.patch(f"/ext/rbac/principals/{bob.id}", json={"is_admin": True}, headers=b)).status_code == 403
    promoted = await ext.patch(f"/ext/rbac/principals/{bob.id}", json={"is_admin": True}, headers=root)
    assert promoted.status_code == 200 and promoted.json()["is_admin"] is True


async def test_bootstrap_admin_cannot_be_demoted_or_disabled(ext, rbac_store):
    boot, _ = await make_user(rbac_store, admin=True)
    _, root = await make_user(rbac_store, admin=True)
    for body in ({"is_admin": False}, {"disabled": True}):
        assert (await ext.patch(f"/ext/rbac/principals/{boot.id}", json=body, headers=root)).status_code == 409


async def test_disable_kills_tokens(ext, rbac_store):
    bob, b = await make_user(rbac_store)
    root_p = await rbac_store.upsert_oidc_user(f"root-{bob.id[:8]}@firefly.ai", "Root", is_bootstrap_admin=False)
    await rbac_store.set_admin(root_p.id, True)
    root = {"Authorization": f"Bearer {(await rbac_store.create_token(root_p.id, 't', None)).token}"}
    assert (await ext.patch(f"/ext/rbac/principals/{bob.id}", json={"disabled": True}, headers=root)).status_code == 200
    assert (await ext.get("/ext/rbac/me", headers=b)).status_code == 401
    assert (
        await ext.patch(f"/ext/rbac/principals/{bob.id}", json={"disabled": False}, headers=root)
    ).status_code == 200
    assert (await ext.get("/ext/rbac/me", headers=b)).status_code == 200


async def test_service_accounts(ext, rbac_store):
    bob, b = await make_user(rbac_store)
    _, root = await make_user(rbac_store, admin=True)
    assert (await ext.post("/ext/rbac/service-accounts", json={"name": "bot"}, headers=b)).status_code == 403
    svc = await ext.post("/ext/rbac/service-accounts", json={"name": "heimdall"}, headers=root)
    assert svc.status_code == 201 and svc.json()["kind"] == "service"
    svc_id = svc.json()["id"]

    minted = await ext.post(f"/ext/rbac/principals/{svc_id}/tokens", json={"name": "prod"}, headers=root)
    assert minted.status_code == 201
    svc_headers = {"Authorization": f"Bearer {minted.json()['token']}"}
    assert (await ext.get("/ext/rbac/me", headers=svc_headers)).json()["kind"] == "service"
    listed = (await ext.get(f"/ext/rbac/principals/{svc_id}/tokens", headers=root)).json()["tokens"]
    assert [t["name"] for t in listed] == ["prod"]

    assert (
        await ext.post(f"/ext/rbac/principals/{bob.id}/tokens", json={"name": "x"}, headers=root)
    ).status_code == 409
    assert (await ext.patch(f"/ext/rbac/principals/{svc_id}", json={"is_admin": True}, headers=root)).status_code == 409


async def test_teams(ext, rbac_store):
    bob, b = await make_user(rbac_store)
    _, root = await make_user(rbac_store, admin=True)
    name = f"team-{bob.id[:8]}"
    assert (await ext.post("/ext/rbac/teams", json={"name": name}, headers=b)).status_code == 403
    created = await ext.post("/ext/rbac/teams", json={"name": name}, headers=root)
    assert created.status_code == 201
    team_id = created.json()["id"]

    assert (await ext.put(f"/ext/rbac/teams/{team_id}/members/{bob.id}", headers=b)).status_code == 403
    assert (await ext.put(f"/ext/rbac/teams/{team_id}/members/{bob.id}", headers=root)).status_code == 204
    teams = (await ext.get("/ext/rbac/teams", headers=b)).json()["teams"]
    assert [m["id"] for t in teams if t["id"] == team_id for m in t["members"]] == [bob.id]

    renamed = await ext.patch(f"/ext/rbac/teams/{team_id}", json={"name": name + "-x"}, headers=root)
    assert renamed.status_code == 200 and renamed.json()["name"] == name + "-x"
    assert (await ext.delete(f"/ext/rbac/teams/{team_id}/members/{bob.id}", headers=root)).status_code == 204
    assert (await ext.delete(f"/ext/rbac/teams/{team_id}", headers=b)).status_code == 403
    assert (await ext.delete(f"/ext/rbac/teams/{team_id}", headers=root)).status_code == 204


async def test_bank_access_and_grants_flow_to_engine(ext, rbac_store):
    alice, a = await make_user(rbac_store)
    bob, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(ext, bank, a) == 200

    access = (await ext.get(f"/ext/rbac/banks/{bank}/access", headers=b)).json()
    assert access["visibility"] == "public" and access["owner"]["id"] == alice.id
    assert access["my_role"] == "writer" and "manage" not in access["my_capabilities"]
    assert (
        await ext.patch(f"/ext/rbac/banks/{bank}/access", json={"visibility": "private"}, headers=b)
    ).status_code == 403

    assert (
        await ext.patch(f"/ext/rbac/banks/{bank}/access", json={"visibility": "private"}, headers=a)
    ).status_code == 200
    assert (await ext.get(f"/ext/rbac/banks/{bank}/access", headers=b)).status_code == 404
    assert await recall(ext, bank, b) == 404

    grant = {"principal_type": "principal", "principal_id": bob.id, "role": "reader"}
    assert (await ext.put(f"/ext/rbac/banks/{bank}/grants", json=grant, headers=b)).status_code == 404
    assert (await ext.put(f"/ext/rbac/banks/{bank}/grants", json=grant, headers=a)).status_code == 200
    assert await recall(ext, bank, b) == 200
    assert await retain(ext, bank, b) == 403
    grants = (await ext.get(f"/ext/rbac/banks/{bank}/access", headers=a)).json()["grants"]
    assert grants == [{"principal_type": "principal", "principal_id": bob.id, "name": "Test User", "role": "reader"}]

    assert (await ext.delete(f"/ext/rbac/banks/{bank}/grants/principal/{bob.id}", headers=a)).status_code == 204
    assert await recall(ext, bank, b) == 404


async def test_owner_transfer(ext, rbac_store):
    _, a = await make_user(rbac_store)
    bob, b = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(ext, bank, a) == 200
    assert (await ext.patch(f"/ext/rbac/banks/{bank}/access", json={"owner_id": bob.id}, headers=a)).status_code == 200
    assert (
        await ext.patch(f"/ext/rbac/banks/{bank}/access", json={"visibility": "private"}, headers=b)
    ).status_code == 200
    assert await recall(ext, bank, a) == 404


async def test_access_via_alias(ext, rbac_store):
    _, a = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(ext, bank, a) == 200
    alias = f"{bank}-alias"
    assert (await ext.post(f"/v1/default/banks/{bank}/aliases", json={"alias": alias}, headers=a)).status_code in (
        200,
        201,
    )
    assert (await ext.get(f"/ext/rbac/banks/{alias}/access", headers=a)).json()["bank_id"] == bank


async def test_rbac_mutations_are_audited(ext, rbac_store, rbac_memory):
    alice, a = await make_user(rbac_store)
    bank = unique_bank()
    assert await retain(ext, bank, a) == 200
    assert (
        await ext.patch(f"/ext/rbac/banks/{bank}/access", json={"visibility": "private"}, headers=a)
    ).status_code == 200
    await rbac_memory._audit_logger.drain()
    pool = await rbac_memory._get_pool()
    rows = await pool.fetch("SELECT action, metadata FROM audit_log WHERE bank_id = $1 AND action LIKE 'rbac.%'", bank)
    assert [r["action"] for r in rows] == ["rbac.update_access"]
    assert alice.id in rows[0]["metadata"]
