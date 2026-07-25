"""SQLite-backed run history for Petrel scans."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_PETREL_DIR = Path.home() / ".petrel"
_DB_PATH = _PETREL_DIR / "history.db"
_SCHEMA_VERSION = 1


def _get_conn() -> sqlite3.Connection:
    _PETREL_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS db_meta (schema_version INTEGER NOT NULL)")
    row = conn.execute("SELECT schema_version FROM db_meta").fetchone()
    current = row["schema_version"] if row else 0
    if current < 1:
        conn.execute("""CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            tag TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS server_snapshots (
            run_id TEXT NOT NULL,
            url TEXT NOT NULL,
            priority_score INTEGER,
            auth_type TEXT,
            record_json TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(id)
        )""")
        if current == 0:
            conn.execute("INSERT INTO db_meta VALUES (1)")
        else:
            conn.execute("UPDATE db_meta SET schema_version = 1")
        conn.commit()


def save_run(tag: str | None = None) -> str:
    """Create a new run entry, return its ID."""
    import uuid

    run_id = str(uuid.uuid4())[:8]
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute("INSERT INTO runs VALUES (?, ?, ?)", (run_id, ts, tag))
    return run_id


def save_snapshot(run_id: str, record: object) -> None:
    """Save an MCPServerRecord to a run snapshot."""
    auth_val = record.auth_state  # type: ignore[attr-defined]
    auth_str = auth_val.value if hasattr(auth_val, "value") else str(auth_val)
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO server_snapshots VALUES (?, ?, ?, ?, ?)",
            (
                run_id,
                record.url,  # type: ignore[attr-defined]
                record.priority_score,  # type: ignore[attr-defined]
                auth_str,
                record.model_dump_json(),  # type: ignore[attr-defined]
            ),
        )


def list_runs() -> list[sqlite3.Row]:
    """Return list of (id, ts, tag, count) rows."""
    with _get_conn() as conn:
        return conn.execute(
            """
            SELECT r.id, r.ts, r.tag, COUNT(s.url) as count
            FROM runs r LEFT JOIN server_snapshots s ON r.id = s.run_id
            GROUP BY r.id ORDER BY r.ts DESC
            """
        ).fetchall()


def diff_runs(tag1: str, tag2: str) -> tuple[set[str], set[str]]:
    """Return (only_in_tag1, only_in_tag2) sets of URLs."""
    with _get_conn() as conn:

        def _get_urls(tag: str) -> set[str]:
            run = conn.execute(
                "SELECT id FROM runs WHERE tag = ? OR id = ? ORDER BY ts DESC LIMIT 1",
                (tag, tag),
            ).fetchone()
            if not run:
                return set()
            rows = conn.execute(
                "SELECT url FROM server_snapshots WHERE run_id = ?", (run["id"],)
            ).fetchall()
            return {r["url"] for r in rows}

        urls1 = _get_urls(tag1)
        urls2 = _get_urls(tag2)
        return urls1 - urls2, urls2 - urls1
