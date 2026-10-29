"""OIDC RS256 verification with tenant identity derived from signed claims."""
import os
from functools import lru_cache

import jwt
from fastapi import Header, HTTPException
from jwt import PyJWKClient


@lru_cache(maxsize=4)
def jwks(url):
    if not url.startswith("https://"):
        raise ValueError("JWKS endpoint must use HTTPS")
    return PyJWKClient(url, timeout=3, cache_jwk_set=True)


def tenant_identity(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    issuer = os.getenv("SENTINELFORGE_OIDC_ISSUER")
    audience = os.getenv("SENTINELFORGE_OIDC_AUDIENCE")
    url = os.getenv("SENTINELFORGE_OIDC_JWKS_URL")
    if not all((issuer, audience, url)):
        raise HTTPException(status_code=503, detail="OIDC not configured")
    try:
        key = jwks(url).get_signing_key_from_jwt(authorization[7:])
        claims = jwt.decode(authorization[7:], key.key, algorithms=["RS256"],
                            issuer=issuer, audience=audience,
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except (jwt.PyJWTError, ValueError, OSError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    tenant = claims.get("tenant_id")
    if not isinstance(tenant, str) or not tenant.isalnum() or len(tenant) > 64:
        raise HTTPException(status_code=403, detail="Invalid tenant claim")
    return tenant
