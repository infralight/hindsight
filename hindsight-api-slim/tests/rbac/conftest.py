"""Fixtures for the fork's RBAC extension tests (hindsight-extensions/rbac).

The extension ships outside the server package, so its sources are put on the
import path here; the core fixtures (`memory`, `pg0_db_url`) come from the parent
conftest.
"""

import sys
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

RBAC_EXTENSION_DIR = Path(__file__).resolve().parents[3] / "hindsight-extensions" / "rbac"
if str(RBAC_EXTENSION_DIR) not in sys.path:
    sys.path.insert(0, str(RBAC_EXTENSION_DIR))


@pytest_asyncio.fixture
async def rbac_memory(memory):
    """The core `memory` engine with the RBAC tables present in its schema."""
    from hindsight_ext_rbac.schema import ensure_schema

    pool = await memory._get_pool()
    async with pool.acquire() as conn:
        await ensure_schema(conn, "public")
    yield memory


@pytest.fixture
def rbac_store(rbac_memory):
    from hindsight_ext_rbac.store import RbacStore

    return RbacStore(rbac_memory._get_pool)


@pytest.fixture
def install_tenant(rbac_memory, pg0_db_url):
    """Build an RbacTenantExtension with the given config and make the engine use it."""
    from hindsight_api.extensions.context import DefaultExtensionContext
    from hindsight_ext_rbac import RbacTenantExtension

    def install(**config: str) -> RbacTenantExtension:
        ext = RbacTenantExtension({"auth_mode": "required", **config})
        ext.set_context(DefaultExtensionContext(database_url=pg0_db_url, memory_engine=rbac_memory))
        rbac_memory._tenant_extension = ext
        rbac_memory._config_resolver.tenant_extension = ext
        return ext

    return install


@pytest.fixture
def install_validator(rbac_memory, pg0_db_url):
    """Make the engine enforce RBAC with a fresh RbacOperationValidator."""
    from hindsight_api.extensions.context import DefaultExtensionContext
    from hindsight_ext_rbac import RbacOperationValidator

    def install() -> RbacOperationValidator:
        validator = RbacOperationValidator({})
        validator.set_context(DefaultExtensionContext(database_url=pg0_db_url, memory_engine=rbac_memory))
        rbac_memory._operation_validator = validator
        return validator

    return install


@pytest.fixture
def rbac_on(install_tenant, install_validator):
    """Tenant (required mode) + validator installed; returns the validator."""
    install_tenant()
    return install_validator()


@pytest_asyncio.fixture
async def api(rbac_memory):
    """HTTP client over the engine (tenant/validator are whatever the test installed)."""
    from hindsight_api.api import create_app

    app = create_app(rbac_memory, initialize_memory=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client
