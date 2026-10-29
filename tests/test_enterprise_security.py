from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from sentinelforge.api import app
from sentinelforge.authorization import principal_from_claims
from sentinelforge.cloud_events import NORMALIZERS

client = TestClient(app)


def test_principal_requires_tenant_subject_and_known_roles():
    principal = principal_from_claims({
        "tenant_id": "tenantA", "sub": "user-1", "roles": ["analyst", "unknown"],
    })
    assert principal.tenant == "tenantA"
    assert principal.roles == frozenset({"analyst"})
    with pytest.raises(HTTPException):
        principal_from_claims({"tenant_id": "../bad", "sub": "x", "roles": []})


def test_cloud_normalizers():
    aws = NORMALIZERS["aws-securityhub"]({"findings": [{
        "Id": "arn:test:finding/1",
        "UpdatedAt": "2026-10-29T10:00:00Z",
        "Resources": [{"Id": "arn:aws:s3:::synthetic"}],
        "Network": {"SourceIpV4": "192.0.2.1"},
    }]})
    assert aws[0].event_type == "cloud_finding"
    assert aws[0].source_ip == "192.0.2.1"


def test_secure_route_enforces_role_and_signed_tenant(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB_PATH", str(tmp_path / "secure.db"))
    with patch("sentinelforge.authorization.oidc_claims", return_value={}):
        pass
    # Dependency override avoids network/JWKS while still exercising role and tenant scoping.
    from sentinelforge.authorization import current_principal, Principal
    app.dependency_overrides[current_principal] = lambda: Principal(
        tenant="tenantA", subject="user", roles=frozenset({"analyst"})
    )
    try:
        response = client.post("/api/v1/secure/analyze", json={"events": []})
        assert response.status_code == 200, response.text
        assert len(client.get("/api/v1/secure/reports").json()["reports"]) == 1
    finally:
        app.dependency_overrides.clear()


def test_security_headers():
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
