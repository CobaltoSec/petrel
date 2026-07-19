"""CLI tests for Petrel — C1-C10 features."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from petrel.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonl(tmp_path: Path, records: list[dict]) -> Path:
    p = tmp_path / "results.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records))
    return p


_CRITICAL_RECORD = {
    "url": "https://critical.example.com",
    "discovered_via": "github",
    "protocol": "streamable-http",
    "auth_state": "none",
    "risk_tier": "CRITICAL",
    "risk_reasons": ["unauthenticated execute_bash"],
    "tools": [{"name": "execute_bash", "risk_tier": "CRITICAL", "schema_risk_params": []}],
    "behind_cloudflare": False,
    "platform": "unknown",
    "endpoint_path": "/api/mcp",
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
}

_LOW_RECORD = {
    "url": "https://low.example.com",
    "discovered_via": "npm",
    "protocol": "streamable-http",
    "auth_state": "bearer",
    "risk_tier": "LOW",
    "risk_reasons": [],
    "tools": [],
    "behind_cloudflare": False,
    "platform": "vercel",
    "endpoint_path": "/mcp",
    "final_url": None,
    "redirect_count": 0,
    "server_name": "LowServer",
    "server_version": "0.1.0",
    "protocol_version": "2024-11-05",
    "server_capabilities": {},
    "server_instructions": None,
    "resources": [],
    "prompts": [],
    "scanned_at": "2026-01-01T00:00:00+00:00",
}


# ---------------------------------------------------------------------------
# C9: probe --json suppresses banner
# ---------------------------------------------------------------------------

def test_probe_json_no_banner(tmp_path: Path, monkeypatch):
    """--json flag → no banner in stdout output."""
    from unittest.mock import AsyncMock, patch
    from petrel.models import MCPServerRecord, Protocol, AuthState, RiskTier, Platform

    mock_record = MCPServerRecord(
        url="https://test.example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        risk_tier=RiskTier.INFO,
        server_name="test",
        platform=Platform.UNKNOWN,
        endpoint_path="/mcp",
    )

    with patch("petrel.cli.probe_url", new_callable=AsyncMock, return_value=mock_record), \
         patch("petrel.cli.score_server", return_value=mock_record):
        result = runner.invoke(app, ["probe", "https://test.example.com", "--json"])

    assert result.exit_code == 0, result.output
    # Banner should NOT appear in stdout
    assert "Petrel" not in result.output
    assert "MCP Internet Scanner" not in result.output
    # Output should be valid JSON
    data = json.loads(result.output.strip())
    assert data["url"] == "https://test.example.com"


# ---------------------------------------------------------------------------
# C2: discover --no-probe writes URL list to file
# ---------------------------------------------------------------------------

def test_discover_no_probe_writes_urls_to_file(tmp_path: Path):
    """--no-probe --output <file> writes candidate URLs to file, returns []."""
    from unittest.mock import AsyncMock, patch

    out_file = tmp_path / "candidates.txt"

    fake_urls = ["https://alpha.example.com", "https://beta.example.com"]

    with patch("petrel.cli.crtsh_search", new_callable=AsyncMock, return_value=["alpha.example.com"]), \
         patch("petrel.cli.hf_spaces_search", new_callable=AsyncMock, return_value=["https://beta.example.com"]), \
         patch("petrel.cli.censys_search", new_callable=AsyncMock, return_value=[]), \
         patch("petrel.cli.github_search", new_callable=AsyncMock, return_value=[]), \
         patch("petrel.cli.npm_search", new_callable=AsyncMock, return_value=[]), \
         patch("petrel.cli.smithery_search", new_callable=AsyncMock, return_value=[]), \
         patch("petrel.cli.pypi_search", new_callable=AsyncMock, return_value=[]), \
         patch("petrel.cli.fofa_search", new_callable=AsyncMock, return_value=[]):
        result = runner.invoke(app, [
            "discover",
            "--no-probe",
            "--output", str(out_file),
            "--no-censys",
            "--no-github",
            "--no-npm",
            "--no-smithery",
            "--no-pypi",
            "--no-fofa",
        ])

    assert result.exit_code == 0, result.output
    assert out_file.exists()
    lines = [l for l in out_file.read_text().splitlines() if l.strip()]
    # Should have the discovered URLs
    assert len(lines) >= 1
    # File should contain URLs (not JSON)
    for line in lines:
        assert line.startswith("http")


# ---------------------------------------------------------------------------
# C4: feed-corvus --source filter
# ---------------------------------------------------------------------------

def test_feed_corvus_source_filter(tmp_path: Path):
    """--source github keeps only github records; npm records are excluded."""
    github_rec = dict(_CRITICAL_RECORD)
    github_rec["discovered_via"] = "github"
    npm_rec = dict(_LOW_RECORD)
    npm_rec["discovered_via"] = "npm"

    jsonl = _make_jsonl(tmp_path, [github_rec, npm_rec])

    result = runner.invoke(app, [
        "feed-corvus",
        str(jsonl),
        "--source", "github",
    ])

    assert result.exit_code == 0, result.output
    # YAML output should mention the github URL but not the npm URL
    assert "critical.example.com" in result.output
    assert "low.example.com" not in result.output


def test_feed_corvus_source_filter_no_match(tmp_path: Path):
    """--source with unknown value prints available sources and exits cleanly."""
    jsonl = _make_jsonl(tmp_path, [_CRITICAL_RECORD])

    result = runner.invoke(app, [
        "feed-corvus",
        str(jsonl),
        "--source", "fofa",
    ])

    assert result.exit_code == 0, result.output
    assert "fofa" in result.output
    # Should list available sources
    assert "github" in result.output


# ---------------------------------------------------------------------------
# C3: stats shows risk distribution
# ---------------------------------------------------------------------------

def test_stats_shows_distribution(tmp_path: Path):
    """stats command counts records by risk tier and prints CRITICAL count."""
    records = [
        _CRITICAL_RECORD,
        dict(_CRITICAL_RECORD, url="https://critical2.example.com"),
        _LOW_RECORD,
    ]
    jsonl = _make_jsonl(tmp_path, records)

    result = runner.invoke(app, ["stats", str(jsonl)])

    assert result.exit_code == 0, result.output
    assert "CRITICAL" in result.output
    assert "LOW" in result.output
    # Should show counts
    assert "3" in result.output  # total or individual counts


def test_stats_tool_breakdown(tmp_path: Path):
    """stats command shows top tool names when tools are present."""
    jsonl = _make_jsonl(tmp_path, [_CRITICAL_RECORD])

    result = runner.invoke(app, ["stats", str(jsonl)])

    assert result.exit_code == 0, result.output
    assert "execute_bash" in result.output


# ---------------------------------------------------------------------------
# C10: diff shows new servers
# ---------------------------------------------------------------------------

def test_diff_shows_new_servers(tmp_path: Path):
    """diff old.jsonl new.jsonl → shows entry present in new but not old."""
    old_path = tmp_path / "old.jsonl"
    new_path = tmp_path / "new.jsonl"

    old_path.write_text(json.dumps(_LOW_RECORD))
    new_path.write_text(
        json.dumps(_LOW_RECORD) + "\n" +
        json.dumps(dict(_CRITICAL_RECORD, url="https://new-server.example.com"))
    )

    result = runner.invoke(app, [
        "diff",
        str(old_path),
        str(new_path),
        "--min-risk", "LOW",
    ])

    assert result.exit_code == 0, result.output
    assert "new-server.example.com" in result.output


def test_diff_shows_escalation(tmp_path: Path):
    """diff detects when a server's risk tier escalates."""
    old_path = tmp_path / "old.jsonl"
    new_path = tmp_path / "new.jsonl"

    shared_url = "https://shared.example.com"
    old_path.write_text(json.dumps(dict(_LOW_RECORD, url=shared_url, risk_tier="LOW")))
    new_path.write_text(json.dumps(dict(_CRITICAL_RECORD, url=shared_url, risk_tier="CRITICAL")))

    result = runner.invoke(app, [
        "diff",
        str(old_path),
        str(new_path),
    ])

    assert result.exit_code == 0, result.output
    assert "shared.example.com" in result.output
    assert "Escalated" in result.output


# ---------------------------------------------------------------------------
# C4: feed-corvus uses endpoint_path
# ---------------------------------------------------------------------------

def test_feed_corvus_uses_endpoint_path(tmp_path: Path):
    """feed-corvus uses record's endpoint_path instead of always /mcp."""
    rec = dict(_CRITICAL_RECORD, endpoint_path="/api/mcp")
    jsonl = _make_jsonl(tmp_path, [rec])

    result = runner.invoke(app, ["feed-corvus", str(jsonl)])

    assert result.exit_code == 0, result.output
    # Should use /api/mcp (from endpoint_path), not /mcp
    assert "/api/mcp" in result.output


def test_feed_corvus_fallback_to_mcp_when_no_path(tmp_path: Path):
    """feed-corvus falls back to /mcp when endpoint_path is None."""
    rec = dict(_CRITICAL_RECORD)
    rec["endpoint_path"] = None
    jsonl = _make_jsonl(tmp_path, [rec])

    result = runner.invoke(app, ["feed-corvus", str(jsonl)])

    assert result.exit_code == 0, result.output
    # URL in YAML output should end with /mcp
    assert "/mcp" in result.output
