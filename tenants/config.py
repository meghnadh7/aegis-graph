"""Tenant config loader. Tenants are JSON files alongside this module."""
from __future__ import annotations
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, Any, List

_TENANTS_DIR = Path(__file__).parent


@lru_cache(maxsize=8)
def load_tenant(tenant_id: str) -> Dict[str, Any]:
    """Load a tenant config dict by id."""
    path = _TENANTS_DIR / f"{tenant_id}.json"
    if not path.exists():
        raise ValueError(f"Unknown tenant: {tenant_id}")
    with path.open() as fh:
        return json.load(fh)


def list_tenants() -> List[str]:
    """List all known tenant ids."""
    return sorted(p.stem for p in _TENANTS_DIR.glob("tenant_*.json"))


def validate_tenant(tenant_id: str) -> None:
    """Raise if tenant is unknown."""
    if tenant_id not in list_tenants():
        raise ValueError(f"Unknown tenant: {tenant_id}")
