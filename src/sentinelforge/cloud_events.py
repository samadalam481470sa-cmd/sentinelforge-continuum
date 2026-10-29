"""Normalize defensive cloud-security findings into SentinelForge events."""
from __future__ import annotations

from datetime import datetime

from sentinelforge.engine import SecurityEvent


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize_aws_securityhub(payload: dict) -> list[SecurityEvent]:
    findings = payload.get("findings", [])
    if not isinstance(findings, list) or len(findings) > 1000:
        raise ValueError("Invalid findings batch")
    events = []
    for finding in findings:
        event_id = str(finding.get("Id", ""))[-100:]
        resource = finding.get("Resources", [{}])[0]
        actor = str(finding.get("UserDefinedFields", {}).get("actor", "aws-securityhub"))[:120]
        events.append(SecurityEvent(
            event_id=event_id.replace(":", "_").replace("/", "_"),
            timestamp=_timestamp(finding["UpdatedAt"]),
            actor=actor,
            source_ip=str(finding.get("Network", {}).get("SourceIpV4", "0.0.0.0"))[:128],
            event_type="cloud_finding",
            success=True,
            asset=str(resource.get("Id", "unknown"))[:120],
            bytes_out=0,
        ))
    return events


def normalize_azure_defender(payload: dict) -> list[SecurityEvent]:
    alerts = payload.get("alerts", [])
    if not isinstance(alerts, list) or len(alerts) > 1000:
        raise ValueError("Invalid alerts batch")
    return [
        SecurityEvent(
            event_id=str(alert["id"])[-100:].replace("/", "_"),
            timestamp=_timestamp(alert["timeGenerated"]),
            actor=str(alert.get("vendorName", "azure-defender"))[:120],
            source_ip=str(alert.get("sourceIp", "0.0.0.0"))[:128],
            event_type="cloud_finding",
            success=True,
            asset=str(alert.get("resourceId", "unknown"))[-120:],
            bytes_out=0,
        )
        for alert in alerts
    ]


def normalize_gcp_scc(payload: dict) -> list[SecurityEvent]:
    findings = payload.get("findings", [])
    if not isinstance(findings, list) or len(findings) > 1000:
        raise ValueError("Invalid findings batch")
    return [
        SecurityEvent(
            event_id=str(item["name"])[-100:].replace("/", "_"),
            timestamp=_timestamp(item["eventTime"]),
            actor="gcp-security-command-center",
            source_ip=str(item.get("sourceProperties", {}).get("sourceIp", "0.0.0.0"))[:128],
            event_type="cloud_finding",
            success=True,
            asset=str(item.get("resourceName", "unknown"))[-120:],
            bytes_out=0,
        )
        for item in findings
    ]


NORMALIZERS = {
    "aws-securityhub": normalize_aws_securityhub,
    "azure-defender": normalize_azure_defender,
    "gcp-scc": normalize_gcp_scc,
}
