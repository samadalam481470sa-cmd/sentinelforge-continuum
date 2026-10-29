"""Read-only demonstration API and bounded security event analyzer."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sentinelforge import platform
from sentinelforge.compliance import assess
from sentinelforge.engine import DEMO_EVENTS, SecurityEvent, analyze, evidence_digest
from sentinelforge.persistence import create_case, list_cases
from sentinelforge.identity import tenant_identity

app = FastAPI(title="SentinelForge Continuum", version="0.1.0")


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    required = os.getenv("SENTINELFORGE_API_KEY")
    if not required or len(required) < 24:
        raise HTTPException(status_code=503, detail="API is not configured for authenticated ingestion")
    if not secrets.compare_digest(x_api_key or "", required):
        raise HTTPException(status_code=401, detail="Invalid API key")


class AnalysisRequest(BaseModel):
    events: list[SecurityEvent] = Field(max_length=10000)


@app.get("/health")
def health():
    return {"status": "ok", "mode": "synthetic-prototype"}


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


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).with_name("dashboard.html"))


@app.post("/api/v1/secure/analyze")
def secure_analyze(payload: AnalysisRequest, tenant: str = Depends(tenant_identity)):
    report = analyze(payload.events)
    digest = evidence_digest(report)
    identifier = platform.save_report(tenant, report, digest)
    return {"report_id": identifier, "sha256": digest, **report}


@app.get("/api/v1/secure/reports")
def secure_reports(tenant: str = Depends(tenant_identity)):
    return {"reports": platform.reports(tenant)}


class CaseRequest(BaseModel):
    report_id: str = Field(min_length=36, max_length=36)


@app.post("/api/v1/secure/cases")
def secure_case(payload: CaseRequest, tenant: str = Depends(tenant_identity)):
    identifier = platform.create_case(tenant, payload.report_id)
    if identifier is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"case_id": identifier, "status": "open"}


@app.get("/api/v1/secure/cases")
def secure_cases(tenant: str = Depends(tenant_identity)):
    return {"cases": platform.cases(tenant)}


class EvidenceRequest(BaseModel):
    evidence: dict[str, list[str]]


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
