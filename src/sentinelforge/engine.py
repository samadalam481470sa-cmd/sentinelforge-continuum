"""Explainable defensive event detection and evidence scoring.

This is a deterministic, synthetic-data prototype, not an autonomous SOC.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from math import log1p

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    timestamp: datetime
    actor: str = Field(min_length=1, max_length=120)
    source_ip: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=80)
    success: bool
    asset: str = Field(min_length=1, max_length=120)
    bytes_out: int = Field(default=0, ge=0, le=10**12)


class Finding(BaseModel):
    rule: str
    severity: str
    score: float
    actors: list[str]
    events: list[str]
    explanation: str


def analyze(events: list[SecurityEvent]) -> dict:
    """Generate interpretable risk alerts with no automatic blocking/remediation."""
    if len(events) > 10000:
        raise ValueError("Batch limit exceeded")
    unique: dict[str, SecurityEvent] = {}
    for event in events:
        if event.event_id in unique:
            raise ValueError("Duplicate event ID")
        unique[event.event_id] = event
    ordered = sorted(events, key=lambda item: (item.timestamp, item.event_id))
    failures: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    asset_access: dict[str, set[str]] = defaultdict(set)
    outbound: list[SecurityEvent] = []
    for event in ordered:
        if event.event_type == "login" and not event.success:
            failures[(event.actor, event.source_ip)].append(event)
        if event.success:
            asset_access[event.actor].add(event.asset)
        if event.event_type == "data_transfer" and event.success and event.bytes_out >= 100_000_000:
            outbound.append(event)

    findings: list[Finding] = []
    for (actor, source), attempts in failures.items():
        for end in range(len(attempts)):
            window = [
                item for item in attempts[:end + 1]
                if 0 <= (attempts[end].timestamp - item.timestamp).total_seconds() <= 600
            ]
            if len(window) >= 5:
                findings.append(Finding(
                    rule="REPEATED_LOGIN_FAILURES", severity="high",
                    score=min(95.0, 50 + 5 * len(window)), actors=[actor],
                    events=[item.event_id for item in window],
                    explanation=f"{len(window)} failed logins from {source} within ten minutes",
                ))
                break

    for event in outbound:
        findings.append(Finding(
            rule="LARGE_OUTBOUND_TRANSFER", severity="medium",
            score=min(90.0, round(35 + 8 * log1p(event.bytes_out / 100_000_000), 2)),
            actors=[event.actor], events=[event.event_id],
            explanation="Large successful outbound transfer merits analyst review",
        ))
    findings.sort(key=lambda item: (-item.score, item.rule, item.events[0]))
    return {
        "events_analyzed": len(ordered),
        "unique_actors": len({event.actor for event in ordered}),
        "assets_touched": len({asset for assets in asset_access.values() for asset in assets}),
        "findings": [item.model_dump() for item in findings],
        "review_required": True,
    }


def evidence_digest(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(serialized.encode()).hexdigest()


DEMO_EVENTS = [
    SecurityEvent(
        event_id=f"login-{index}",
        timestamp=datetime(2026, 10, 1, 12, index, tzinfo=timezone.utc),
        actor="synthetic-operator", source_ip="192.0.2.10",
        event_type="login", success=False, asset="demo-gateway",
    )
    for index in range(7)
]
DEMO_EVENTS += [SecurityEvent(
    event_id="transfer-1",
    timestamp=datetime(2026, 10, 1, 13, tzinfo=timezone.utc),
    actor="synthetic-service", source_ip="198.51.100.20",
    event_type="data_transfer", success=True, asset="demo-storage", bytes_out=500_000_000,
)]
