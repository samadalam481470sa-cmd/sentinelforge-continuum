"""Tenant-scoped report, case, and audit persistence for local development."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


def now() -> str:
    return datetime.now(UTC).isoformat()


@contextmanager
def connection():
    path = os.getenv("SENTINELFORGE_DB_PATH", "/tmp/sentinelforge.db")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS secure_reports(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,
          created_at TEXT NOT NULL,digest TEXT NOT NULL,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS secure_cases(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,
          report_id TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS secure_audit_events(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,
          action TEXT NOT NULL,object_id TEXT NOT NULL,created_at TEXT NOT NULL,
          previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS secure_reports_tenant
          ON secure_reports(tenant,created_at);
        CREATE INDEX IF NOT EXISTS secure_cases_tenant
          ON secure_cases(tenant,created_at);
        CREATE INDEX IF NOT EXISTS secure_audit_tenant
          ON secure_audit_events(tenant,created_at);
        """)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _audit(db, tenant: str, actor: str, action: str, object_id: str) -> str:
    previous = db.execute(
        "SELECT event_hash FROM secure_audit_events "
        "WHERE tenant=? ORDER BY rowid DESC LIMIT 1",
        (tenant,),
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else "GENESIS"
    created = now()
    material = "|".join((previous_hash, tenant, actor, action, object_id, created))
    event_hash = hashlib.sha256(material.encode()).hexdigest()
    identifier = str(uuid4())
    db.execute(
        "INSERT INTO secure_audit_events "
        "(id,tenant,actor,action,object_id,created_at,previous_hash,event_hash) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (identifier, tenant, actor, action, object_id, created, previous_hash, event_hash),
    )
    return identifier


def audit(tenant: str, actor: str, action: str, object_id: str) -> str:
    with connection() as db:
        return _audit(db, tenant, actor, action, object_id)


def save_report(
    tenant: str,
    actor_or_report: str | dict,
    report_or_digest: dict | str,
    digest: str | None = None,
) -> str:
    if digest is None:
        actor = "legacy"
        report = actor_or_report
        resolved_digest = report_or_digest
    else:
        actor = actor_or_report
        report = report_or_digest
        resolved_digest = digest
    if not isinstance(actor, str) or not isinstance(report, dict) or not isinstance(resolved_digest, str):
        raise TypeError("Invalid report arguments")
    identifier = str(uuid4())
    with connection() as db:
        db.execute(
            "INSERT INTO secure_reports "
            "(id,tenant,actor,created_at,digest,body) VALUES (?,?,?,?,?,?)",
            (identifier, tenant, actor, now(), resolved_digest, json.dumps(report)),
        )
        _audit(db, tenant, actor, "report_created", identifier)
    return identifier


def reports(tenant: str) -> list[dict]:
    with connection() as db:
        rows = db.execute(
            "SELECT id,actor,created_at,digest FROM secure_reports "
            "WHERE tenant=? ORDER BY created_at DESC LIMIT 100",
            (tenant,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_case(
    tenant: str, actor_or_report_id: str, report_id: str | None = None
) -> str | None:
    if report_id is None:
        actor = "legacy"
        resolved_report_id = actor_or_report_id
    else:
        actor = actor_or_report_id
        resolved_report_id = report_id
    identifier = str(uuid4())
    with connection() as db:
        found = db.execute(
            "SELECT 1 FROM secure_reports WHERE id=? AND tenant=?",
            (resolved_report_id, tenant),
        ).fetchone()
        if not found:
            return None
        db.execute(
            "INSERT INTO secure_cases "
            "(id,tenant,actor,report_id,status,created_at) VALUES (?,?,?,?,?,?)",
            (identifier, tenant, actor, resolved_report_id, "open", now()),
        )
        _audit(db, tenant, actor, "case_created", identifier)
    return identifier


def cases(tenant: str) -> list[dict]:
    with connection() as db:
        return [
            dict(row)
            for row in db.execute(
                "SELECT * FROM secure_cases "
                "WHERE tenant=? ORDER BY created_at DESC LIMIT 100",
                (tenant,),
            ).fetchall()
        ]


def audit_events(tenant: str) -> list[dict]:
    with connection() as db:
        return [
            dict(row)
            for row in db.execute(
                "SELECT id,actor,action,object_id,created_at,previous_hash,event_hash "
                "FROM secure_audit_events WHERE tenant=? ORDER BY rowid DESC LIMIT 200",
                (tenant,),
            ).fetchall()
        ]
