"""Tests for PETREL-LONGITUDINAL: server_run_snapshots, tool_name_hash, JSONL fields."""
from __future__ import annotations

import hashlib
import json

import pytest

from petrel import store as _store
from petrel.models import AuthState, MCPServerRecord, Platform, Protocol, RiskTier


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(_store, "DB_PATH", tmp_path / "runs.db")


def test_store_snapshots(tmp_db):
    run_id = _store.create_run(label="test-run", source="test")
    records = [
        MCPServerRecord(
            url="https://example.com",
            protocol=Protocol.STREAMABLE_HTTP,
            auth_state=AuthState.NONE,
            risk_tier=RiskTier.CRITICAL,
            priority_score=90,
            capability_cluster=["exec+network"],
            tool_name_hash="deadbeef12345678",
            petrel_version="0.9.0",
        ),
        MCPServerRecord(
            url="https://another.com",
            protocol=Protocol.STREAMABLE_HTTP,
            auth_state=AuthState.REQUIRED,
            risk_tier=RiskTier.HIGH,
            priority_score=65,
            capability_cluster=[],
        ),
    ]
    n = _store.insert_run_snapshots(run_id, records)
    assert n == 2

    conn = _store.get_db()
    rows = conn.execute(
        "SELECT * FROM server_run_snapshots WHERE run_id=? ORDER BY url", (run_id,)
    ).fetchall()
    conn.close()

    assert len(rows) == 2
    row = dict(rows[0])  # another.com sorts first
    assert row["url"] == "https://another.com"
    assert row["risk_tier"] == "HIGH"
    assert json.loads(row["capability_cluster"]) == []

    row2 = dict(rows[1])  # example.com
    assert row2["url"] == "https://example.com"
    assert row2["tool_name_hash"] == "deadbeef12345678"
    assert row2["risk_tier"] == "CRITICAL"
    assert json.loads(row2["capability_cluster"]) == ["exec+network"]
    assert row2["petrel_version"] == "0.9.0"

    # Query by URL
    conn = _store.get_db()
    by_url = conn.execute(
        "SELECT run_id FROM server_run_snapshots WHERE url=?", ("https://example.com",)
    ).fetchall()
    conn.close()
    assert len(by_url) == 1
    assert by_url[0]["run_id"] == run_id


def test_tool_name_hash_order_invariant():
    def _hash(names: list[str]) -> str:
        return hashlib.sha256(json.dumps(sorted(names)).encode()).hexdigest()[:16]

    # Order invariant
    assert _hash(["read_file", "write_file", "bash"]) == _hash(["bash", "read_file", "write_file"])
    # Different tools → different hash
    assert _hash(["tool_a"]) != _hash(["tool_b"])
    # Empty list produces a stable hash
    assert len(_hash([])) == 16
    assert _hash([]) == _hash([])
    # Single item
    assert len(_hash(["only_one"])) == 16


def test_jsonl_fields():
    r = MCPServerRecord(
        url="https://test.com",
        protocol=Protocol.STREAMABLE_HTTP,
        capability_cluster=["exec+network", "read+messaging"],
        tool_name_hash="abc123def45678ef",
        petrel_version="0.9.0",
    )
    data = r.model_dump(mode="json")
    assert data["capability_cluster"] == ["exec+network", "read+messaging"]
    assert data["petrel_version"] == "0.9.0"
    assert data["tool_name_hash"] == "abc123def45678ef"

    # Defaults: None / empty list
    r2 = MCPServerRecord(url="https://minimal.com")
    data2 = r2.model_dump(mode="json")
    assert data2["tool_name_hash"] is None
    assert data2["capability_cluster"] == []
    assert data2["petrel_version"] is None
