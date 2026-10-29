"""Read-only demonstration API and bounded security event analyzer."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sentinelforge.engine import DEMO_EVENTS, SecurityEvent, analyze, evidence_digest

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
