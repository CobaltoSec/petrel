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
            avg_priority_score REAL DEFAULT NULL,
            auth_added INTEGER DEFAULT 0,
            taken_down INTEGER DEFAULT 0,
            url_changed INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS server_history (
            url TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_confirmed_at TEXT NOT NULL,
            last_run_id INTEGER,
            status TEXT NOT NULL DEFAULT 'active',
            consecutive_confirmed_runs INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS server_run_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            tool_name_hash TEXT,
            tool_count INTEGER,
            auth_state TEXT,
            risk_tier TEXT,
            priority_score REAL,
            capability_cluster TEXT,
            petrel_version TEXT,
            scanned_at TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(id)
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_url ON server_run_snapshots(url);
        CREATE INDEX IF NOT EXISTS idx_snapshots_run ON server_run_snapshots(run_id);
    """)
    # Migrate existing DBs that predate these columns — silently skip if present.
    for _col_ddl in (
        "ALTER TABLE runs ADD COLUMN auth_pct REAL DEFAULT NULL",
        "ALTER TABLE runs ADD COLUMN avg_priority_score REAL DEFAULT NULL",
        "ALTER TABLE server_history ADD COLUMN consecutive_confirmed_runs INTEGER DEFAULT 1",
        "ALTER TABLE runs ADD COLUMN auth_added INTEGER DEFAULT 0",
        "ALTER TABLE runs ADD COLUMN taken_down INTEGER DEFAULT 0",
        "ALTER TABLE runs ADD COLUMN url_changed INTEGER DEFAULT 0",
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


def finish_run(
    run_id: int,
    records: list,
    *,
    auth_added: int = 0,
    taken_down: int = 0,
    url_changed: int = 0,
) -> None:
    """Finalise a run row with confirmed record stats and optional disappearance breakdown.

    Args:
        run_id: ID returned by create_run().
        records: List of confirmed MCPServerRecord objects for this run.
        auth_added: Servers from a previous run that now require authentication.
        taken_down: Servers from a previous run that are unreachable / gone.
        url_changed: Servers from a previous run that responded on a different URL.
    """
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
        "auth_pct=?, avg_priority_score=?, auth_added=?, taken_down=?, url_changed=? WHERE id=?",
        (
            datetime.now(timezone.utc).isoformat(),
            confirmed, critical, confirmed,
            auth_pct, avg_priority_score,
            auth_added, taken_down, url_changed,
            run_id,
        ),
    )
    conn.commit()
    conn.close()
    try:
        from cobaltosec_hub import emit as _hub_emit
        _hub_emit("petrel.run.completed", {
            "confirmed_count": confirmed,
            "critical_count": critical,
            "jsonl_path": "",
            "label": "",
        })
    except Exception:
        pass


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


def insert_run_snapshots(run_id: int, records: list) -> int:
    """Bulk-insert one snapshot per confirmed record into server_run_snapshots.

    petrel_version is resolved from importlib.metadata if not already set on the record.
    Returns the number of rows inserted.
    """
    import importlib.metadata as _meta
    import json as _json
    try:
        _pv = _meta.version("cobaltosec-petrel")
    except Exception:
        _pv = None

    rows = []
    for r in records:
        scanned_at = getattr(r, "scanned_at", None)
        if hasattr(scanned_at, "isoformat"):
            scanned_at = scanned_at.isoformat()
        else:
            scanned_at = str(scanned_at) if scanned_at else None
        pv = getattr(r, "petrel_version", None) or _pv
        _auth = getattr(r, "auth_state", "")
        _tier = getattr(r, "risk_tier", "")
        rows.append((
            run_id,
            getattr(r, "url", ""),
            getattr(r, "tool_name_hash", None),
            len(getattr(r, "tools", [])),
            _auth.value if hasattr(_auth, "value") else str(_auth),
            _tier.value if hasattr(_tier, "value") else str(_tier),
            getattr(r, "priority_score", None),
            _json.dumps(getattr(r, "capability_cluster", [])),
            pv,
            scanned_at,
        ))

    if not rows:
        return 0

    conn = get_db()
    conn.executemany(
        "INSERT INTO server_run_snapshots "
        "(run_id,url,tool_name_hash,tool_count,auth_state,risk_tier,"
        "priority_score,capability_cluster,petrel_version,scanned_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)


def get_trend(metric: str) -> list:
    allowed = {
        "confirmed_count",
        "critical_count",
        "target_count",
        "auth_pct",
        "avg_priority_score",
        "auth_added",
        "taken_down",
        "url_changed",
    }
    if metric not in allowed:
        return []
    conn = get_db()
    rows = conn.execute(
        f"SELECT id, label, started_at, {metric} FROM runs ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
