from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from sentinelforge.api import app
from sentinelforge.authorization import Principal, current_principal
from sentinelforge.identity import oidc_claims
from sentinelforge import platform

client = TestClient(app)


def test_oidc_validates_signature_configuration_and_claims(monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_OIDC_ISSUER", "https://issuer.example/")
    monkeypatch.setenv("SENTINELFORGE_OIDC_AUDIENCE", "sentinelforge")
    monkeypatch.setenv("SENTINELFORGE_OIDC_JWKS_URL", "https://issuer.example/jwks")
    claims = {
        "sub": "user-1", "tenant_id": "tenantA", "roles": ["analyst"],
        "iss": "https://issuer.example/", "aud": "sentinelforge",
    }
    with patch("sentinelforge.identity.jwks") as client_mock:
        client_mock.return_value.get_signing_key_from_jwt.return_value.key = "public-key"
        with patch("sentinelforge.identity.jwt.decode", return_value=claims) as decode:
            assert oidc_claims("Bearer signed-token")["tenant_id"] == "tenantA"
            assert decode.call_args.kwargs["algorithms"] == ["RS256"]


def test_missing_bearer_is_rejected():
    with pytest.raises(HTTPException) as error:
        oidc_claims(None)
    assert error.value.status_code == 401


def test_tenant_report_case_and_audit_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB_PATH", str(tmp_path / "tenant.db"))
    report = platform.save_report("tenantA", "analyst-1", {"findings": []}, "abc")
    case = platform.create_case("tenantA", "analyst-1", report)
    assert case is not None
    assert platform.reports("tenantB") == []
    assert platform.cases("tenantB") == []
    events = list(reversed(platform.audit_events("tenantA")))
    assert len(events) == 2
    assert events[0]["previous_hash"] == "GENESIS"
    assert events[1]["previous_hash"] == events[0]["event_hash"]


def test_cloud_endpoint_is_tenant_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB_PATH", str(tmp_path / "cloud.db"))
    app.dependency_overrides[current_principal] = lambda: Principal(
        tenant="tenantA", subject="analyst-1", roles=frozenset({"analyst"})
    )
    try:
        response = client.post("/api/v1/secure/cloud/analyze", json={
            "provider": "aws-securityhub",
            "payload": {"findings": [{
                "Id": "arn:aws:securityhub:demo:finding/1",
                "UpdatedAt": "2026-10-29T10:00:00Z",
                "Resources": [{"Id": "arn:aws:s3:::fictional"}],
            }]},
        })
        assert response.status_code == 200, response.text
        assert response.json()["normalized_events"] == 1
        assert response.json()["findings"][0]["rule"] == "CLOUD_SECURITY_FINDING"
        assert len(client.get("/api/v1/secure/reports").json()["reports"]) == 1
    finally:
        app.dependency_overrides.clear()


def test_viewer_cannot_analyze(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB_PATH", str(tmp_path / "viewer.db"))
    app.dependency_overrides[current_principal] = lambda: Principal(
        tenant="tenantA", subject="viewer-1", roles=frozenset({"viewer"})
    )
    try:
        assert client.post("/api/v1/secure/analyze", json={"events": []}).status_code == 403
        assert client.get("/api/v1/secure/reports").status_code == 200
    finally:
        app.dependency_overrides.clear()
