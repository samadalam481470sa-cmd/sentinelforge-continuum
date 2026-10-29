"""Tenant-scoped event and compliance case persistence for local development."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection():
    path = os.getenv("SENTINELFORGE_DB_PATH", "/tmp/sentinelforge.db")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS reports(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,created_at TEXT NOT NULL,
          digest TEXT NOT NULL,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cases(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,report_id TEXT NOT NULL,
          status TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS reports_tenant ON reports(tenant,created_at);
        CREATE INDEX IF NOT EXISTS cases_tenant ON cases(tenant,created_at);
        """)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def save_report(tenant, report, digest):
    identifier = str(uuid4())
    with connection() as db:
        db.execute("INSERT INTO reports VALUES (?,?,?,?,?)",
                   (identifier, tenant, now(), digest, json.dumps(report)))
    return identifier


def reports(tenant):
    with connection() as db:
        rows = db.execute(
            "SELECT id,created_at,digest FROM reports WHERE tenant=? ORDER BY created_at DESC LIMIT 100",
            (tenant,)).fetchall()
    return [dict(row) for row in rows]


def create_case(tenant, report_id):
    identifier = str(uuid4())
    with connection() as db:
        found = db.execute("SELECT 1 FROM reports WHERE id=? AND tenant=?",
                           (report_id, tenant)).fetchone()
        if not found:
            return None
        db.execute("INSERT INTO cases VALUES (?,?,?,?,?)",
                   (identifier, tenant, report_id, "open", now()))
    return identifier


def cases(tenant):
    with connection() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM cases WHERE tenant=? ORDER BY created_at DESC LIMIT 100",
            (tenant,)).fetchall()]
