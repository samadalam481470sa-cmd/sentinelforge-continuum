"""Cloud audit event normalization for defensive analysis."""
from datetime import datetime

from sentinelforge.engine import SecurityEvent


def cloudtrail_event(record: dict) -> SecurityEvent:
    event_id = record["eventID"]
    name = record.get("eventName", "")
    actor = str(record.get("userIdentity", {}).get("principalId", "unknown"))
    response = record.get("responseElements") or {}
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00")),
        actor=actor[:120],
        source_ip=str(record.get("sourceIPAddress", "unknown"))[:128],
        event_type="login" if name == "ConsoleLogin" else "cloud_api",
        success=not record.get("errorCode") and response.get("ConsoleLogin") != "Failure",
        asset=str(record.get("eventSource", "aws"))[:120],
    )
