from fastapi.testclient import TestClient

from sentinelforge.api import app
from sentinelforge.compliance import assess
from sentinelforge.persistence import create_case, list_cases


def test_tenant_case_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB", str(tmp_path / "cases.db"))
    identifier = create_case("tenant_a", {"findings": []})
    assert list_cases("tenant_a")[0]["id"] == identifier
    assert list_cases("tenant_b") == []


def test_compliance_evidence_is_not_certification():
    result = assess({"AC-2": ["review-123"]})
    assert result["controls"][0]["status"] == "evidence-submitted"
    assert result["controls"][1]["status"] == "missing-evidence"


def test_case_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("SENTINELFORGE_API_KEY", "test-secret-with-at-least-24-characters")
    client = TestClient(app)
    headers = {"X-API-Key": "test-secret-with-at-least-24-characters"}
    assert client.post("/api/v1/cases", headers=headers, json={"events": []}).status_code == 200
    assert len(client.get("/api/v1/cases", headers=headers).json()["cases"]) == 1
    assert client.post("/api/v1/compliance/assess", headers=headers, json={"evidence": {}}).status_code == 200
