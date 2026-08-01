"""E2E tests for Petrel v10 features — re-probe diff, trend metrics, feed-shrike."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import yaml
from pytest_httpx import HTTPXMock
from typer.testing import CliRunner

from petrel.cli import app
from petrel.diff import classify_disappearance, classify_disappearances_batch

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonl(tmp_path: Path, records: list[dict]) -> Path:
    p = tmp_path / "results.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records))
    return p


def _make_record(**kwargs) -> dict:
    base = {
        "url": "https://example.com",
        "discovered_via": "github",
        "protocol": "streamable-http",
        "auth_state": "none",
        "risk_tier": "HIGH",
        "risk_reasons": [],
        "tools": [],
        "behind_cloudflare": False,
        "platform": "unknown",
        "endpoint_path": "/mcp",
        "final_url": None,
        "redirect_count": 0,
        "server_name": "TestServer",
        "server_version": "1.0.0",
        "protocol_version": "2024-11-05",
        "server_capabilities": {},
        "server_instructions": None,
        "resources": [],
        "prompts": [],
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "priority_score": 60,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Re-probe in classify_disappearance
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disappearance_reconfirmed_by_reprobe(httpx_mock: HTTPXMock):
    """
    Server was in prev_run but not in new_run; re-probe returns a valid
    MCPServerRecord → classified as 'intermittent', not 'disappeared'.
    """
    from petrel.models import MCPServerRecord, Protocol, AuthState, RiskTier, Platform

    mock_result = MCPServerRecord(
        url="https://intermittent.example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        risk_tier=RiskTier.LOW,
        risk_reasons=[],
        tools=[],
        discovered_via="github",
        behind_cloudflare=False,
        platform=Platform.UNKNOWN,
        endpoint_path="/mcp",
    )
    # is_confirmed_mcp == True when protocol != UNKNOWN

    with patch(
        "petrel.fingerprint.probe.probe_url",
        new=AsyncMock(return_value=mock_result),
    ):
        record = {"url": "https://intermittent.example.com"}
        result = await classify_disappearance(record)

    assert result == "intermittent"


@pytest.mark.asyncio
async def test_disappearance_confirmed_by_reprobe_failure(httpx_mock: HTTPXMock):
    """
    Re-probe fails (raises Exception) and raw HTTP check also fails →
    classified as 'taken_down'.
    """
    with patch(
        "petrel.fingerprint.probe.probe_url",
        new=AsyncMock(side_effect=Exception("network error")),
    ):
        httpx_mock.add_exception(
            httpx.ConnectError("connection refused"),
            method="POST",
            url="https://gone.example.com/tools/list",
        )
        record = {"url": "https://gone.example.com"}
        result = await classify_disappearance(record)

    assert result == "taken_down"


@pytest.mark.asyncio
async def test_reprobe_returns_none_falls_through_to_raw(httpx_mock: HTTPXMock):
    """
    probe_url returns None (not MCP) → falls through to raw HTTP check → auth_added.
    """
    with patch(
        "petrel.fingerprint.probe.probe_url",
        new=AsyncMock(return_value=None),
    ):
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/tools/list",
            status_code=401,
        )
        record = {"url": "https://auth.example.com"}
        result = await classify_disappearance(record)

    assert result == "auth_added"


@pytest.mark.asyncio
async def test_critical_disappearance_has_verified_gone_flag(httpx_mock: HTTPXMock):
    """
    CRITICAL server (priority_score >= 80) confirmed as taken_down via batch →
    verified_gone=True is attached to the record dict.
    """
    with patch(
        "petrel.fingerprint.probe.probe_url",
        new=AsyncMock(return_value=None),
    ):
        httpx_mock.add_exception(
            httpx.ConnectError("connection refused"),
            method="POST",
            url="https://critical.example.com/tools/list",
        )
        records = [{"url": "https://critical.example.com", "priority_score": 85}]
        groups = await classify_disappearances_batch(records)

    assert len(groups["taken_down"]) == 1
    assert groups["taken_down"][0].get("verified_gone") is True


# ---------------------------------------------------------------------------
# Trend metrics in store.py
# ---------------------------------------------------------------------------

def _make_mock_record(auth_state: str, priority_score: int):
    """Return a simple object with auth_state and priority_score attributes."""
    obj = types.SimpleNamespace(auth_state=auth_state, priority_score=priority_score)
    return obj


def _isolated_db(tmp_path: Path) -> sqlite3.Connection:
    """Open an isolated SQLite DB in tmp_path (not ~/.petrel/runs.db)."""
    db_path = tmp_path / "test_runs.db"
    conn = sqlite3.connect(str(db_path))
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
    """)
    conn.commit()
    return conn


def test_trend_includes_auth_pct(tmp_path: Path):
    """
    finish_run with 3 records (2 with auth, 1 without) → auth_pct stored as ~66.67.
    Verified by directly querying an isolated SQLite DB.
    """
    import petrel.store as store_mod

    db_path = tmp_path / "runs.db"

    with patch.object(store_mod, "DB_PATH", db_path):
        run_id = store_mod.create_run("auth-pct-test", "github")
        records = [
            _make_mock_record("bearer", 60),
            _make_mock_record("api-key", 70),
            _make_mock_record("none", 30),
        ]
        store_mod.finish_run(run_id, records)
        rows = store_mod.list_runs()

    assert rows, "Expected at least one run row"
    row = next(r for r in rows if r["id"] == run_id)
    assert row["auth_pct"] == pytest.approx(66.67, abs=0.1)


def test_trend_includes_avg_priority_score(tmp_path: Path):
    """
    finish_run with scores [40, 60, 80] → avg_priority_score stored as 60.0.
    """
    import petrel.store as store_mod

    db_path = tmp_path / "runs.db"

    with patch.object(store_mod, "DB_PATH", db_path):
        run_id = store_mod.create_run("avg-score-test", "github")
        records = [
            _make_mock_record("none", 40),
            _make_mock_record("none", 60),
            _make_mock_record("bearer", 80),
        ]
        store_mod.finish_run(run_id, records)
        rows = store_mod.list_runs()

    row = next(r for r in rows if r["id"] == run_id)
    assert row["avg_priority_score"] == pytest.approx(60.0, abs=0.01)


def test_trend_handles_empty_run(tmp_path: Path):
    """
    finish_run with no records → auth_pct=None, avg_priority_score=None, no crash.
    """
    import petrel.store as store_mod

    db_path = tmp_path / "runs.db"

    with patch.object(store_mod, "DB_PATH", db_path):
        run_id = store_mod.create_run("empty-run-test", "github")
        store_mod.finish_run(run_id, [])
        rows = store_mod.list_runs()

    row = next(r for r in rows if r["id"] == run_id)
    assert row["auth_pct"] is None
    assert row["avg_priority_score"] is None
    assert row["confirmed_count"] == 0


# ---------------------------------------------------------------------------
# feed-shrike CLI command
# ---------------------------------------------------------------------------

def test_feed_shrike_filters_github_source(tmp_path: Path):
    """Only servers with discovered_via == 'github' appear in output YAML."""
    out = tmp_path / "out.yaml"
    records = [
        _make_record(url="https://gh.example.com", discovered_via="github", priority_score=70),
        _make_record(url="https://npm.example.com", discovered_via="npm", priority_score=70),
    ]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(app, ["feed-shrike", str(jsonl), "--output", str(out)])
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    urls = [t["url"] for t in data["targets"]]
    assert "https://gh.example.com" in urls
    assert "https://npm.example.com" not in urls


def test_feed_shrike_min_priority_filter(tmp_path: Path):
    """Only servers with priority_score >= min_priority are included."""
    out = tmp_path / "out.yaml"
    records = [
        _make_record(url="https://hi.example.com", priority_score=80, auth_state="bearer"),
        _make_record(url="https://lo.example.com", priority_score=20, auth_state="bearer"),
    ]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(
        app, ["feed-shrike", str(jsonl), "--output", str(out), "--min-priority", "60"]
    )
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    urls = [t["url"] for t in data["targets"]]
    assert "https://hi.example.com" in urls
    assert "https://lo.example.com" not in urls


def test_feed_shrike_generates_valid_yaml(tmp_path: Path):
    """Output file is parseable YAML with expected shape."""
    out = tmp_path / "out.yaml"
    records = [_make_record(url="https://check.example.com", priority_score=70)]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(app, ["feed-shrike", str(jsonl), "--output", str(out)])
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    assert "targets" in data
    assert isinstance(data["targets"], list)
    assert len(data["targets"]) == 1

    target = data["targets"][0]
    assert "url" in target
    assert "priority_score" in target
    assert "auth" in target
    assert "source" in target
    assert target["source"] == "petrel"


def test_feed_shrike_creates_output_dir(tmp_path: Path):
    """Output directory is created if it does not exist."""
    nested_out = tmp_path / "a" / "b" / "c" / "out.yaml"
    records = [_make_record(url="https://dir.example.com", priority_score=70)]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(app, ["feed-shrike", str(jsonl), "--output", str(nested_out)])
    assert result.exit_code == 0, result.output
    assert nested_out.exists()


def test_feed_shrike_empty_result_no_crash(tmp_path: Path):
    """No matching servers (wrong source) → informative message, exit 0."""
    records = [
        _make_record(url="https://npm.example.com", discovered_via="npm", priority_score=70)
    ]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(app, ["feed-shrike", str(jsonl)])
    # exit 0, no exception, message about no matching servers
    assert result.exit_code == 0
    assert result.output  # some output was printed


def test_feed_shrike_sorts_by_priority_descending(tmp_path: Path):
    """Targets in output YAML are sorted by priority_score descending."""
    out = tmp_path / "out.yaml"
    records = [
        _make_record(url="https://med.example.com", priority_score=60),
        _make_record(url="https://hi.example.com", priority_score=90),
        _make_record(url="https://lo.example.com", priority_score=70),
    ]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(app, ["feed-shrike", str(jsonl), "--output", str(out)])
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    scores = [t["priority_score"] for t in data["targets"]]
    assert scores == sorted(scores, reverse=True)


def test_feed_shrike_auth_none_high_included_regardless_of_score(tmp_path: Path):
    """
    Server with auth=none AND risk_tier=HIGH is included even if
    priority_score < min_priority.
    """
    out = tmp_path / "out.yaml"
    records = [
        _make_record(
            url="https://danger.example.com",
            auth_state="none",
            risk_tier="HIGH",
            priority_score=10,  # below min_priority=50
        ),
    ]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(
        app, ["feed-shrike", str(jsonl), "--output", str(out), "--min-priority", "50"]
    )
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    urls = [t["url"] for t in data["targets"]]
    assert "https://danger.example.com" in urls
