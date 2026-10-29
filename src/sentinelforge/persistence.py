"""Local durable event and case store; demo use only."""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


@contextmanager
def connection():
    path = os.getenv("SENTINELFORGE_DB", "/tmp/sentinelforge.db")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, status TEXT NOT NULL, report TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_cases_tenant ON cases(tenant)")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_case(tenant: str, report: dict) -> str:
    identifier = str(uuid4())
    with connection() as db:
        db.execute("INSERT INTO cases VALUES (?,?,?,?)", (identifier, tenant, "open", json.dumps(report)))
    return identifier


def list_cases(tenant: str) -> list[dict]:
    with connection() as db:
        rows = db.execute("SELECT id,status,report FROM cases WHERE tenant=? ORDER BY rowid DESC LIMIT 100", (tenant,)).fetchall()
    return [{"id": row[0], "status": row[1], "report": json.loads(row[2])} for row in rows]
