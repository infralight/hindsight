"""Fixtures for the fork's RBAC extension tests (hindsight-extensions/rbac).

The extension ships outside the server package, so its sources are put on the
import path here; the core fixtures (`memory`, `pg0_db_url`) come from the parent
conftest.
"""

import sys
from pathlib import Path

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
