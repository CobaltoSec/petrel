"""One-shot backfill: insert server_run_snapshots from existing JSONL runs.

Usage:
    .venv/Scripts/python.exe scripts/backfill_snapshots.py

Processes runs registered in runs.db that have a jsonl_path pointing to an
existing file. Skips runs that already have snapshot rows. Orphan JSONLs
(files with no matching run in DB) are listed at the end.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from petrel.models import MCPServerRecord
from petrel.store import get_db, insert_run_snapshots


def main() -> None:
    conn = get_db()
    runs = conn.execute("SELECT id, label, jsonl_path FROM runs ORDER BY id").fetchall()
    conn.close()

    total = 0
    processed_paths: set[str] = set()

    for run in runs:
        run_id, label, jsonl_path = run["id"], run["label"], run["jsonl_path"]
        if not jsonl_path:
            print(f"Run {run_id} ({label}): no jsonl_path — skip")
            continue

        p = Path(jsonl_path)
        processed_paths.add(str(p.resolve()))

        if not p.exists():
            print(f"Run {run_id} ({label}): {p} not found — skip")
            continue

        check = get_db()
        existing = check.execute(
            "SELECT COUNT(*) FROM server_run_snapshots WHERE run_id=?", (run_id,)
        ).fetchone()[0]
        check.close()
        if existing:
            print(f"Run {run_id} ({label}): {existing} rows already — skip")
            continue

        records: list[MCPServerRecord] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(MCPServerRecord.model_validate(json.loads(line)))
            except Exception as e:
                print(f"  parse error in run {run_id}: {e}")

        if not records:
            print(f"Run {run_id} ({label}): no valid records — skip")
            continue

        n = insert_run_snapshots(run_id, records)
        total += n
        print(f"Run {run_id} ({label}): inserted {n} snapshots from {p}")

    # Report orphan JSONLs (files with no run_id in DB)
    search_dirs = [
        Path(__file__).parent.parent / "outputs",
        Path(__file__).parent.parent / "runs",
        Path.home() / ".petrel",
    ]
    orphans: list[Path] = []
    for d in search_dirs:
        if d.exists():
            for f in sorted(d.glob("*.jsonl")):
                if str(f.resolve()) not in processed_paths:
                    orphans.append(f)

    if orphans:
        print(f"\nOrphan JSONLs (no run_id in DB) — {len(orphans)} file(s):")
        for f in orphans:
            lines = sum(1 for l in f.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip())
            print(f"  {f}  ({lines} records)")
        print("  → To backfill an orphan, manually INSERT a row into `runs` with the jsonl_path,")
        print("    then re-run this script.")

    print(f"\nDone. Total: {total} snapshot rows inserted.")


if __name__ == "__main__":
    main()
