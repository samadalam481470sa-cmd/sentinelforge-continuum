"""OIDC authorization primitives with tenant and role claims."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException

from sentinelforge.identity import oidc_claims


@dataclass(frozen=True)
class Principal:
    tenant: str
    subject: str
    roles: frozenset[str]


def principal_from_claims(claims: dict) -> Principal:
    tenant = claims.get("tenant_id")
    subject = claims.get("sub")
    raw_roles = claims.get("roles", [])
    if not isinstance(tenant, str) or not tenant.isalnum() or len(tenant) > 64:
        raise HTTPException(status_code=403, detail="Invalid tenant claim")
    if not isinstance(subject, str) or not subject or len(subject) > 200:
        raise HTTPException(status_code=403, detail="Invalid subject claim")
    if not isinstance(raw_roles, list) or any(not isinstance(role, str) for role in raw_roles):
        raise HTTPException(status_code=403, detail="Invalid roles claim")
    roles = frozenset(role for role in raw_roles if role in {"viewer", "analyst", "admin"})
    return Principal(tenant=tenant, subject=subject, roles=roles)


def current_principal(claims: Annotated[dict, Depends(oidc_claims)]) -> Principal:
    return principal_from_claims(claims)


ROLE_LEVEL = {"viewer": 1, "analyst": 2, "admin": 3}


def require_role(required: str):
    required_level = ROLE_LEVEL[required]

    def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        level = max((ROLE_LEVEL.get(role, 0) for role in principal.roles), default=0)
        if level < required_level:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return principal

    return dependency
