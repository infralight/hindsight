"""RbacTenantExtension: bearer credential -> principal on RequestContext.tenant_id."""

import pytest
from rbac_helpers import make_user, unique_bank, unique_email

from hindsight_api import RequestContext
from hindsight_api.extensions import AuthenticationError


async def test_required_mode_rejects_anonymous(install_tenant, api):
    install_tenant(auth_mode="required")
    assert (await api.get("/v1/default/banks")).status_code == 401


async def test_optional_mode_allows_anonymous(install_tenant, api):
    ext = install_tenant(auth_mode="optional")
    assert (await api.get("/v1/default/banks")).status_code == 200
    ctx = RequestContext()
    await ext.authenticate(ctx)
    assert ctx.tenant_id == "anonymous" and ctx.api_key_id is None


async def test_garbage_token_is_401_in_optional_mode(install_tenant, api):
    install_tenant(auth_mode="optional")
    for bearer in ("hsp_not-a-real-token", "garbage", "eyJ.e30.sig"):
        response = await api.get("/v1/default/banks", headers={"Authorization": f"Bearer {bearer}"})
        assert response.status_code == 401, bearer


async def test_api_token_sets_principal(install_tenant, rbac_store, api):
    ext = install_tenant()
    alice, headers = await make_user(rbac_store)
    assert (await api.get("/v1/default/banks", headers=headers)).status_code == 200

    ctx = RequestContext(api_key=headers["Authorization"].removeprefix("Bearer "))
    tenant = await ext.authenticate(ctx)
    assert tenant.schema_name == "public"
    assert ctx.tenant_id == alice.id and ctx.api_key_id


async def test_disabled_principal_token_401_next_request(install_tenant, rbac_store, api):
    install_tenant()
    alice, headers = await make_user(rbac_store)
    assert (await api.get("/v1/default/banks", headers=headers)).status_code == 200
    await rbac_store.set_disabled(alice.id, True)
    assert (await api.get("/v1/default/banks", headers=headers)).status_code == 401


async def test_oidc_token_upserts_and_bootstraps_admin(install_tenant, rbac_store, monkeypatch):
    from hindsight_ext_rbac.identity import OidcIdentity

    admin_email, user_email = unique_email(), unique_email()
    ext = install_tenant(
        oidc_issuer="https://accounts.google.com",
        oidc_audiences="client-1",
        allowed_email_domains="firefly.ai",
        admin_emails=f"other@firefly.ai, {admin_email.upper()}",
    )
    identities = {"tok-admin": OidcIdentity(admin_email, "Root"), "tok-user": OidcIdentity(user_email, "Pat")}

    async def fake_verify(token: str) -> OidcIdentity:
        return identities[token]

    monkeypatch.setattr(ext._verifier, "verify", fake_verify)

    admin_ctx, user_ctx = RequestContext(api_key="tok-admin"), RequestContext(api_key="tok-user")
    await ext.authenticate(admin_ctx)
    await ext.authenticate(user_ctx)
    assert admin_ctx.api_key_id == "oidc"
    assert (await rbac_store.get_principal(admin_ctx.tenant_id)).is_admin
    assert not (await rbac_store.get_principal(user_ctx.tenant_id)).is_admin

    await rbac_store.set_disabled(user_ctx.tenant_id, True)
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key="tok-user"))


async def test_oidc_not_configured_rejects_non_api_tokens(install_tenant):
    ext = install_tenant()
    with pytest.raises(AuthenticationError):
        await ext.authenticate(RequestContext(api_key="eyJ.e30.sig"))


def test_refuses_mcp_auth_token_env(monkeypatch):
    from hindsight_ext_rbac import RbacTenantExtension

    monkeypatch.setenv("HINDSIGHT_API_MCP_AUTH_TOKEN", "static")
    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN"):
        RbacTenantExtension({})


@pytest.mark.parametrize(
    "config",
    [
        pytest.param({"auth_mode": "sometimes"}, id="bad-mode"),
        pytest.param({"oidc_issuer": "https://accounts.google.com"}, id="issuer-without-audience"),
        pytest.param(
            {"oidc_issuer": "https://accounts.google.com", "oidc_audiences": "c"}, id="issuer-without-domains"
        ),
    ],
)
def test_rejects_bad_config(config):
    from hindsight_ext_rbac import RbacTenantExtension

    with pytest.raises(ValueError):
        RbacTenantExtension(config)


async def test_audit_flag_not_writable_by_non_admin(install_tenant, rbac_store, api):
    install_tenant()
    _, user = await make_user(rbac_store)
    _, admin = await make_user(rbac_store, admin=True)
    bank = unique_bank()
    assert (await api.put(f"/v1/default/banks/{bank}", json={"name": "x"}, headers=user)).status_code == 200

    body = {"updates": {"audit_log_enabled": False}}
    denied = await api.patch(f"/v1/default/banks/{bank}/config", json=body, headers=user)
    assert denied.status_code == 400 and "audit_log_enabled" in denied.text
    allowed = await api.patch(f"/v1/default/banks/{bank}/config", json=body, headers=admin)
    assert allowed.status_code == 200
