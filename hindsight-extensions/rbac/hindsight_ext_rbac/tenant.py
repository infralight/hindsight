"""Tenant extension: who is calling. (Stub until authentication lands.)"""

from __future__ import annotations

from pathlib import Path

from hindsight_api.extensions.tenant import TenantExtension


class RbacTenantExtension(TenantExtension):
    @classmethod
    def alembic_version_locations(cls) -> list[str]:
        return [str(Path(__file__).parent / "alembic_versions")]
