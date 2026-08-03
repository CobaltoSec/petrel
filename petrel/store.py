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
            jsonl_path TEXT,
            auth_pct REAL DEFAULT NULL,
            avg_priority_score REAL DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS server_history (
            url TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_confirmed_at TEXT NOT NULL,
            last_run_id INTEGER,
            status TEXT NOT NULL DEFAULT 'active',
            consecutive_confirmed_runs INTEGER DEFAULT 1
        );
    """)
    # Migrate existing DBs that predate these columns — silently skip if present.
    for _col_ddl in (
        "ALTER TABLE runs ADD COLUMN auth_pct REAL DEFAULT NULL",
        "ALTER TABLE runs ADD COLUMN avg_priority_score REAL DEFAULT NULL",
        "ALTER TABLE server_history ADD COLUMN consecutive_confirmed_runs INTEGER DEFAULT 1",
    ):
        try:
            conn.execute(_col_ddl)
        except sqlite3.OperationalError:
            pass  # column already exists
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

    # auth_pct: % of confirmed servers with real authentication (not 'none'/'unknown')
    _no_auth = {"none", "unknown"}
    with_auth = sum(
        1 for r in records
        if str(getattr(r, "auth_state", "none")).lower() not in _no_auth
    )
    auth_pct: Optional[float] = round(100.0 * with_auth / confirmed, 2) if confirmed else None

    # avg_priority_score: mean priority_score across all confirmed servers
    scores = [s for r in records if (s := getattr(r, "priority_score", None)) is not None]
    avg_priority_score: Optional[float] = round(sum(scores) / len(scores), 2) if scores else None

    conn = get_db()
    conn.execute(
        "UPDATE runs SET finished_at=?, confirmed_count=?, critical_count=?, target_count=?, "
        "auth_pct=?, avg_priority_score=? WHERE id=?",
        (
            datetime.now(timezone.utc).isoformat(),
            confirmed, critical, confirmed,
            auth_pct, avg_priority_score,
            run_id,
        ),
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
            """INSERT INTO server_history (url, first_seen, last_confirmed_at, last_run_id, status, consecutive_confirmed_runs)
               VALUES (?, ?, ?, ?, 'active', 1)
               ON CONFLICT(url) DO UPDATE SET
                   last_confirmed_at           = excluded.last_confirmed_at,
                   last_run_id                 = excluded.last_run_id,
                   status                      = 'active',
                   consecutive_confirmed_runs  = CASE
                       WHEN server_history.status = 'active' THEN server_history.consecutive_confirmed_runs + 1
                       ELSE 1
                   END
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
                "UPDATE server_history SET status='decayed', consecutive_confirmed_runs=0 WHERE url=?",
                (url,),
            )
            decayed_count += 1

    total_active: int = conn.execute(
        "SELECT COUNT(*) FROM server_history WHERE status='active'"
    ).fetchone()[0]

    conn.commit()
    conn.close()

    return {"new": new_count, "decayed": decayed_count, "total_active": total_active}


def get_consecutive_runs_map(urls: list[str]) -> dict[str, int]:
    """Return {url: consecutive_confirmed_runs} for the given URLs.

    URLs not in server_history (i.e. never confirmed before) are omitted
    from the result, which means the caller should treat missing keys as 0.
    """
    if not urls:
        return {}
    conn = get_db()
    placeholders = ",".join("?" * len(urls))
    rows = conn.execute(
        f"SELECT url, consecutive_confirmed_runs FROM server_history WHERE url IN ({placeholders})",
        urls,
    ).fetchall()
    conn.close()
    return {row["url"]: row["consecutive_confirmed_runs"] or 0 for row in rows}


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
    allowed = {"confirmed_count", "critical_count", "target_count", "auth_pct", "avg_priority_score"}
    if metric not in allowed:
        return []
    conn = get_db()
    rows = conn.execute(
        f"SELECT id, label, started_at, {metric} FROM runs ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
