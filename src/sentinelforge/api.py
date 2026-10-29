"""SentinelForge defensive security analytics API."""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sentinelforge import platform
from sentinelforge.authorization import Principal, require_role
from sentinelforge.cloud_events import NORMALIZERS
from sentinelforge.compliance import assess
from sentinelforge.engine import DEMO_EVENTS, SecurityEvent, analyze, evidence_digest
from sentinelforge.hardening import metrics, security_middleware
from sentinelforge.persistence import create_case, list_cases

app = FastAPI(title="SentinelForge Continuum", version="0.2.0")
app.middleware("http")(security_middleware)
app.add_api_route("/metrics", metrics, methods=["GET"], include_in_schema=False)

Analyst = Annotated[Principal, Depends(require_role("analyst"))]
Viewer = Annotated[Principal, Depends(require_role("viewer"))]


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    required = os.getenv("SENTINELFORGE_API_KEY")
    if not required or len(required) < 24:
        raise HTTPException(status_code=503, detail="API is not configured for authenticated ingestion")
    if not secrets.compare_digest(x_api_key or "", required):
        raise HTTPException(status_code=401, detail="Invalid API key")


class AnalysisRequest(BaseModel):
    events: list[SecurityEvent] = Field(max_length=10000)


class CaseRequest(BaseModel):
    report_id: str = Field(min_length=36, max_length=36)


class EvidenceRequest(BaseModel):
    evidence: dict[str, list[str]]


class CloudRequest(BaseModel):
    provider: str = Field(pattern=r"^(aws-securityhub|azure-defender|gcp-scc)$")
    payload: dict


@app.get("/health")
def health():
    return {"status": "ok", "mode": "synthetic-prototype", "version": "0.2.0"}


@app.get("/api/v1/demo")
def demo():
    return analyze(DEMO_EVENTS)


@app.post("/api/v1/analyze", dependencies=[Depends(require_key)])
def analyze_events(payload: AnalysisRequest):
    try:
        report = analyze(payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {**report, "sha256": evidence_digest(report)}


@app.post("/api/v1/secure/analyze")
def secure_analyze(payload: AnalysisRequest, principal: Analyst):
    report = analyze(payload.events)
    digest = evidence_digest(report)
    identifier = platform.save_report(principal.tenant, principal.subject, report, digest)
    return {"report_id": identifier, "sha256": digest, **report}


@app.post("/api/v1/secure/cloud/analyze")
def secure_cloud_analyze(payload: CloudRequest, principal: Analyst):
    try:
        events = NORMALIZERS[payload.provider](payload.payload)
        report = analyze(events)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Invalid cloud finding payload") from exc
    digest = evidence_digest(report)
    identifier = platform.save_report(principal.tenant, principal.subject, report, digest)
    return {
        "provider": payload.provider,
        "normalized_events": len(events),
        "report_id": identifier,
        "sha256": digest,
        **report,
    }


@app.get("/api/v1/secure/reports")
def secure_reports(principal: Viewer):
    return {"reports": platform.reports(principal.tenant)}


@app.post("/api/v1/secure/cases")
def secure_case(payload: CaseRequest, principal: Analyst):
    identifier = platform.create_case(principal.tenant, principal.subject, payload.report_id)
    if identifier is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"case_id": identifier, "status": "open"}


@app.get("/api/v1/secure/cases")
def secure_cases(principal: Viewer):
    return {"cases": platform.cases(principal.tenant)}


@app.post("/api/v1/secure/compliance/assess")
def secure_compliance(payload: EvidenceRequest, principal: Analyst):
    result = assess(payload.evidence)
    platform.audit(principal.tenant, principal.subject, "compliance_assessment", "controls")
    return result


@app.get("/api/v1/secure/audit")
def secure_audit(principal: Viewer):
    return {"events": platform.audit_events(principal.tenant)}


@app.post("/api/v1/compliance/assess", dependencies=[Depends(require_key)])
def compliance_assessment(payload: EvidenceRequest):
    return assess(payload.evidence)


@app.post("/api/v1/cases", dependencies=[Depends(require_key)])
def save_case(payload: AnalysisRequest):
    report = analyze(payload.events)
    return {"case_id": create_case("demo", report), "findings": report["findings"]}


@app.get("/api/v1/cases", dependencies=[Depends(require_key)])
def cases():
    return {"cases": list_cases("demo")}


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).with_name("dashboard.html"))
