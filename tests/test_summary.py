"""Tests for generate_run_summary (post-run funnel markdown)."""
from __future__ import annotations

from pathlib import Path

import pytest

from petrel.models import AuthState, MCPServerRecord, Protocol, RiskTier
from petrel.summary import generate_run_summary


def _make_record(
    url: str,
    risk_tier: RiskTier = RiskTier.INFO,
    auth_state: AuthState = AuthState.NONE,
    protocol: Protocol = Protocol.STREAMABLE_HTTP,
) -> MCPServerRecord:
    return MCPServerRecord(
        url=url,
        protocol=protocol,
        auth_state=auth_state,
        risk_tier=risk_tier,
    )


def test_generate_run_summary_creates_file(tmp_path):
    """Summary file is created in output_dir with the expected name pattern."""
    records = [
        _make_record("https://a.example.com", RiskTier.CRITICAL, AuthState.NONE),
        _make_record("https://b.example.com", RiskTier.HIGH, AuthState.BEARER),
    ]
    decay = {"new": 1, "decayed": 0, "total_active": 2}

    path = generate_run_summary(42, records, decay, candidate_count=100, output_dir=tmp_path)

    assert path.exists()
    assert path.name.startswith("run-42-")
    assert path.suffix == ".md"


def test_generate_run_summary_funnel_counts(tmp_path):
    """Summary markdown contains correct funnel row values."""
    records = [
        _make_record("https://c1.example.com", RiskTier.CRITICAL, AuthState.NONE),
        _make_record("https://h1.example.com", RiskTier.HIGH, AuthState.NONE),
        _make_record("https://l1.example.com", RiskTier.LOW, AuthState.BEARER),
    ]
    decay = {"new": 2, "decayed": 5, "total_active": 10}

    path = generate_run_summary(7, records, decay, candidate_count=50, output_dir=tmp_path)
    content = path.read_text()

    assert "Candidatos totales" in content
    assert "| 50 |" in content          # candidate_count
    assert "Confirmados MCP" in content
    assert "| 3 |" in content           # 3 confirmed
    assert "CRITICAL" in content
    assert "| 1 |" in content           # 1 critical
    assert "Sin autenticacion" in content
    assert "| 2 |" in content           # 2 without auth (CRITICAL + HIGH)
    assert "Nuevos esta run" in content
    assert "| 2 |" in content
    assert "Decaidos" in content
    assert "| 5 |" in content


def test_generate_run_summary_fallback_candidate_count(tmp_path):
    """When candidate_count=0, falls back to len(results) for total."""
    records = [_make_record("https://x.example.com")]
    decay = {"new": 1, "decayed": 0, "total_active": 1}

    path = generate_run_summary(1, records, decay, candidate_count=0, output_dir=tmp_path)
    content = path.read_text()

    # confirmed == candidates => 100%
    assert "| 1 |" in content
    assert "100%" in content
