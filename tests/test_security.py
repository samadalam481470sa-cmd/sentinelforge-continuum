from datetime import datetime, timezone

from fastapi.testclient import TestClient

from sentinelforge.api import app
from sentinelforge.engine import DEMO_EVENTS, SecurityEvent, analyze, evidence_digest

client = TestClient(app)


def test_demo_detection():
    results = analyze(DEMO_EVENTS)
    assert results["events_analyzed"] == 8
    rules = {finding["rule"] for finding in results["findings"]}
    assert rules == {"REPEATED_LOGIN_FAILURES", "LARGE_OUTBOUND_TRANSFER"}
    assert analyze(DEMO_EVENTS) == results


def test_protected_endpoint(monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_API_KEY", "a-long-test-key-for-synthetic-demo")
    assert client.post("/api/v1/analyze", json={"events": []}).status_code == 401
    assert client.post("/api/v1/analyze", headers={
        "X-API-Key": "a-long-test-key-for-synthetic-demo",
    }, json={"events": []}).status_code == 200


def test_invalid_and_duplicate_events(monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_API_KEY", "a-long-test-key-for-synthetic-demo")
    event = DEMO_EVENTS[0].model_dump(mode="json")
    assert client.post("/api/v1/analyze", headers={
        "X-API-Key": "a-long-test-key-for-synthetic-demo",
    }, json={"events": [event, event]}).status_code == 422
    invalid = {**event, "bytes_out": -1}
    assert client.post("/api/v1/analyze", headers={
        "X-API-Key": "a-long-test-key-for-synthetic-demo",
    }, json={"events": [invalid]}).status_code == 422


def test_artifact_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["status"] == "ok"
    assert evidence_digest({"a": 1, "b": 2}) == evidence_digest({"b": 2, "a": 1})


def test_no_unbounded_alerts():
    events = [SecurityEvent(
        event_id=f"ok-{i}", timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        actor=f"user-{i}", source_ip="192.0.2.5", event_type="login",
        success=True, asset="test",
    ) for i in range(100)]
    assert analyze(events)["findings"] == []
