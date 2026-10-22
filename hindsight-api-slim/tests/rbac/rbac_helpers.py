"""Helpers shared by the RBAC tests (kept out of conftest so tests can import them)."""

import uuid


def unique_email() -> str:
    return f"u-{uuid.uuid4().hex[:10]}@firefly.ai"


def unique_bank() -> str:
    return f"rbac-{uuid.uuid4().hex[:10]}"


async def make_user(store, *, admin: bool = False):
    """A user principal plus an API token for it: (principal, bearer headers)."""
    principal = await store.upsert_oidc_user(unique_email(), "Test User", is_bootstrap_admin=admin)
    token = await store.create_token(principal.id, "test", expires_at=None)
    return principal, {"Authorization": f"Bearer {token.token}"}
