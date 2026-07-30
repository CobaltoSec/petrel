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
        CREATE TABLE IF NOT EXISTS server_history (
            url TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_confirmed_at TEXT NOT NULL,
            last_run_id INTEGER,
            status TEXT NOT NULL DEFAULT 'active'
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


def update_server_history(run_id: int, confirmed_urls: list[str]) -> dict:
    """Update server_history with this run's confirmed URLs and decay stale ones.

    For each URL in *confirmed_urls*: upsert with status='active' and
    last_confirmed_at=now. For active rows NOT in this run whose
    last_confirmed_at is older than 30 days: mark status='decayed'.

    Returns dict with keys: new, decayed, total_active.
    """
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    thirty_days_ago = (now - timedelta(days=30)).isoformat()
    now_iso = now.isoformat()

    conn = get_db()

    # Fetch existing URLs to count truly new ones
    existing = {
        row[0]
        for row in conn.execute("SELECT url FROM server_history").fetchall()
    }

    new_count = 0
    confirmed_set = set(confirmed_urls)

    for url in confirmed_urls:
        if url not in existing:
            new_count += 1
        conn.execute(
            """INSERT INTO server_history (url, first_seen, last_confirmed_at, last_run_id, status)
               VALUES (?, ?, ?, ?, 'active')
               ON CONFLICT(url) DO UPDATE SET
                   last_confirmed_at = excluded.last_confirmed_at,
                   last_run_id       = excluded.last_run_id,
                   status            = 'active'
            """,
            (url, now_iso, now_iso, run_id),
        )

    # Decay: active rows absent from this run and not seen in 30 days
    stale = conn.execute(
        "SELECT url FROM server_history WHERE status='active' AND last_confirmed_at < ?",
        (thirty_days_ago,),
    ).fetchall()

    decayed_count = 0
    for (url,) in stale:
        if url not in confirmed_set:
            conn.execute(
                "UPDATE server_history SET status='decayed' WHERE url=?", (url,)
            )
            decayed_count += 1

    total_active: int = conn.execute(
        "SELECT COUNT(*) FROM server_history WHERE status='active'"
    ).fetchone()[0]

    conn.commit()
    conn.close()

    return {"new": new_count, "decayed": decayed_count, "total_active": total_active}


def decay_stats() -> dict:
    """Return counts of active and decayed servers in server_history."""
    conn = get_db()
    active: int = conn.execute(
        "SELECT COUNT(*) FROM server_history WHERE status='active'"
    ).fetchone()[0]
    decayed: int = conn.execute(
        "SELECT COUNT(*) FROM server_history WHERE status='decayed'"
    ).fetchone()[0]
    conn.close()
    return {"active_count": active, "decayed_count": decayed}


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
