"""SQLite run history for Petrel — lightweight alternative to storage.py."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = Path.home() / ".petrel" / "runs.db"


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            source TEXT,
            target_count INTEGER DEFAULT 0,
            confirmed_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            jsonl_path TEXT
        );
    """)
    conn.commit()
    return conn


def create_run(label: Optional[str], source: str, jsonl_path: Optional[str] = None) -> int:
    from datetime import datetime, timezone
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO runs (label, started_at, source, jsonl_path) VALUES (?,?,?,?)",
        (label, datetime.now(timezone.utc).isoformat(), source, jsonl_path)
    )
    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return run_id


def finish_run(run_id: int, records: list) -> None:
    from datetime import datetime, timezone
    confirmed = len(records)
    critical = sum(1 for r in records if getattr(r, "priority_score", 0) >= 80)
    conn = get_db()
    conn.execute(
        "UPDATE runs SET finished_at=?, confirmed_count=?, critical_count=?, target_count=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), confirmed, critical, confirmed, run_id)
    )
    conn.commit()
    conn.close()


def list_runs() -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_trend(metric: str) -> list:
    allowed = {"confirmed_count", "critical_count", "target_count"}
    if metric not in allowed:
        return []
    conn = get_db()
    rows = conn.execute(
        f"SELECT id, label, started_at, {metric} FROM runs ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
