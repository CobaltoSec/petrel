"""Tests for store decay model (server_history table)."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

import petrel.store as store_module
from petrel.store import decay_stats, get_db, update_server_history


def _patch_db(tmp_path: Path):
    """Patch DB_PATH to an isolated temp file."""
    return patch.object(store_module, "DB_PATH", tmp_path / "test_runs.db")


def test_update_server_history_new_urls(tmp_path):
    """New URLs are inserted with status=active and counted correctly."""
    with _patch_db(tmp_path):
        result = update_server_history(1, ["https://a.example.com", "https://b.example.com"])

    assert result["new"] == 2
    assert result["decayed"] == 0
    assert result["total_active"] == 2


def test_update_server_history_upsert_does_not_double_count(tmp_path):
    """Re-confirming an existing URL keeps it active and is not counted as new."""
    with _patch_db(tmp_path):
        update_server_history(1, ["https://stable.example.com"])
        result = update_server_history(2, ["https://stable.example.com"])

    assert result["new"] == 0
    assert result["total_active"] == 1


def test_update_server_history_decays_stale_urls(tmp_path):
    """Active URLs not seen in 30+ days and absent from this run become decayed."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()

    with _patch_db(tmp_path):
        # Manually insert an old active record
        conn = get_db()
        conn.execute(
            "INSERT INTO server_history (url, first_seen, last_confirmed_at, last_run_id, status)"
            " VALUES (?,?,?,?,?)",
            ("https://old.example.com", old_date, old_date, 1, "active"),
        )
        conn.commit()
        conn.close()

        # Run with a different URL — old one should decay
        result = update_server_history(2, ["https://fresh.example.com"])

    assert result["new"] == 1
    assert result["decayed"] == 1
    assert result["total_active"] == 1


def test_decay_stats_counts(tmp_path):
    """decay_stats returns correct active/decayed counts after multiple runs."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()

    with _patch_db(tmp_path):
        # Insert one old record manually
        conn = get_db()
        conn.execute(
            "INSERT INTO server_history (url, first_seen, last_confirmed_at, last_run_id, status)"
            " VALUES (?,?,?,?,?)",
            ("https://gone.example.com", old_date, old_date, 1, "active"),
        )
        conn.commit()
        conn.close()

        # Run updates that will decay the old one
        update_server_history(2, ["https://live.example.com"])
        stats = decay_stats()

    assert stats["active_count"] == 1
    assert stats["decayed_count"] == 1
