"""CLI tests for Petrel — C1-C10 features."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from petrel.cli import app
from petrel.models import SourceResult

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

    _empty = SourceResult(urls=[])
    with patch("petrel.cli.crtsh_search", new_callable=AsyncMock, return_value=SourceResult(urls=["alpha.example.com"])), \
         patch("petrel.cli.hf_spaces_search", new_callable=AsyncMock, return_value=SourceResult(urls=["https://beta.example.com"])), \
         patch("petrel.cli.censys_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.github_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.npm_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.smithery_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.pypi_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.fofa_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.shodan_search", new_callable=AsyncMock, return_value=_empty), \
         patch("petrel.cli.registries_search", new_callable=AsyncMock, return_value=_empty):
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
            "--no-shodan",
            "--no-registries",
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


# ---------------------------------------------------------------------------
# SR-02: no-auth tag solo cuando auth_state == "none"
# ---------------------------------------------------------------------------

def test_sr02_no_auth_tag_only_when_auth_none(tmp_path: Path):
    import yaml

    records = [
        {"url": "https://a.com", "protocol": "streamable-http", "risk_tier": "CRITICAL",
         "auth_state": "bearer", "discovered_via": "github", "tools": [], "risk_reasons": [],
         "endpoint_path": "/mcp", "final_url": None, "resources": [], "prompts": [],
         "platform": "unknown", "behind_cloudflare": False, "server_capabilities": {},
         "server_instructions": None, "server_name": None, "server_version": None,
         "protocol_version": None, "redirect_count": 0, "scanned_at": "2026-01-01T00:00:00+00:00"},
        {"url": "https://b.com", "protocol": "streamable-http", "risk_tier": "HIGH",
         "auth_state": "none", "discovered_via": "github", "tools": [], "risk_reasons": [],
         "endpoint_path": "/mcp", "final_url": None, "resources": [], "prompts": [],
         "platform": "unknown", "behind_cloudflare": False, "server_capabilities": {},
         "server_instructions": None, "server_name": None, "server_version": None,
         "protocol_version": None, "redirect_count": 0, "scanned_at": "2026-01-01T00:00:00+00:00"},
    ]
    jsonl = _make_jsonl(tmp_path, records)
    out = tmp_path / "targets.yaml"

    result = runner.invoke(app, ["feed-corvus", str(jsonl), "--output", str(out)])
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    targets = {t["url"].split("/mcp")[0].replace("https://", ""): t for t in data["targets"]}

    # a.com tiene bearer auth — NO debe tener no-auth tag
    a_tags = targets.get("a.com", {}).get("tags", [])
    assert "no-auth" not in a_tags, f"Bearer server should not have no-auth tag: {a_tags}"

    # b.com tiene auth_state=none — SÍ debe tener no-auth tag
    b_tags = targets.get("b.com", {}).get("tags", [])
    assert "no-auth" in b_tags, f"No-auth server should have no-auth tag: {b_tags}"


# ---------------------------------------------------------------------------
# SR-04: risk_tier presente en todas las entradas + CRITICAL primero
# ---------------------------------------------------------------------------

def test_sr04_risk_tier_present_and_sorted(tmp_path: Path):
    import yaml

    records = [
        {"url": "https://low.com", "protocol": "streamable-http", "risk_tier": "LOW",
         "auth_state": "bearer", "discovered_via": "github", "tools": [], "risk_reasons": [],
         "endpoint_path": "/mcp", "final_url": None, "resources": [], "prompts": [],
         "platform": "unknown", "behind_cloudflare": False, "server_capabilities": {},
         "server_instructions": None, "server_name": None, "server_version": None,
         "protocol_version": None, "redirect_count": 0, "scanned_at": "2026-01-01T00:00:00+00:00"},
        {"url": "https://critical.com", "protocol": "streamable-http", "risk_tier": "CRITICAL",
         "auth_state": "none", "discovered_via": "github", "tools": [], "risk_reasons": [],
         "endpoint_path": "/mcp", "final_url": None, "resources": [], "prompts": [],
         "platform": "unknown", "behind_cloudflare": False, "server_capabilities": {},
         "server_instructions": None, "server_name": None, "server_version": None,
         "protocol_version": None, "redirect_count": 0, "scanned_at": "2026-01-01T00:00:00+00:00"},
    ]
    jsonl = _make_jsonl(tmp_path, records)
    out = tmp_path / "targets.yaml"

    result = runner.invoke(app, ["feed-corvus", str(jsonl), "--output", str(out)])
    assert result.exit_code == 0, result.output

    data = yaml.safe_load(out.read_text())
    targets = data["targets"]

    # risk_tier presente en todas las entradas
    for t in targets:
        assert "risk_tier" in t, f"risk_tier missing from entry: {t}"

    # CRITICAL va primero
    assert targets[0]["risk_tier"] == "CRITICAL"
    assert targets[1]["risk_tier"] == "LOW"


# ---------------------------------------------------------------------------
# DISC-002: URL normalization pre-dedup
# ---------------------------------------------------------------------------

def test_disc002_url_normalization_dedup(tmp_path: Path):
    """DISC-002: URLs that normalize to the same form are deduplicated before probing."""
    from unittest.mock import AsyncMock, patch

    # crtsh returns domain "foo.example.com" → converted to "https://foo.example.com"
    # hf returns "https://foo.example.com/" → strips trailing slash → same normalized URL
    # Result: only 1 candidate, not 2
    with patch("petrel.cli.crtsh_search", new_callable=AsyncMock,
               return_value=SourceResult(urls=["foo.example.com"])), \
         patch("petrel.cli.hf_spaces_search", new_callable=AsyncMock,
               return_value=SourceResult(urls=["https://foo.example.com/"])), \
         patch("petrel.cli.shodan_search", new_callable=AsyncMock, return_value=SourceResult(urls=[])), \
         patch("petrel.cli.registries_search", new_callable=AsyncMock, return_value=SourceResult(urls=[])):
        result = runner.invoke(app, [
            "discover", "--no-probe",
            "--no-censys", "--no-github", "--no-npm", "--no-smithery", "--no-pypi", "--no-fofa",
            "--no-shodan", "--no-registries",
        ])

    assert result.exit_code == 0, result.output
    assert "Candidates:" in result.output
    # Only 1 unique candidate after normalization
    assert "Candidates: 1" in result.output


# ---------------------------------------------------------------------------
# DISC-011: SourceResult error visibility
# ---------------------------------------------------------------------------

def test_disc011_source_error_printed(tmp_path: Path):
    """DISC-011: When a source returns SourceResult with error → error is visible in output."""
    from unittest.mock import AsyncMock, patch

    with patch("petrel.cli.crtsh_search", new_callable=AsyncMock,
               return_value=SourceResult(urls=[], error="connection refused")), \
         patch("petrel.cli.hf_spaces_search", new_callable=AsyncMock,
               return_value=SourceResult(urls=[])), \
         patch("petrel.cli.shodan_search", new_callable=AsyncMock, return_value=SourceResult(urls=[])), \
         patch("petrel.cli.registries_search", new_callable=AsyncMock, return_value=SourceResult(urls=[])):
        result = runner.invoke(app, [
            "discover", "--no-probe",
            "--no-censys", "--no-github", "--no-npm", "--no-smithery", "--no-pypi", "--no-fofa",
            "--no-shodan", "--no-registries",
        ])

    assert result.exit_code == 0, result.output
    assert "connection refused" in result.output or "ERROR" in result.output


# ---------------------------------------------------------------------------
# PERF-01: Incremental JSONL output
# ---------------------------------------------------------------------------

def test_perf01_incremental_output(tmp_path: Path):
    """PERF-01: Results written to file incrementally via on_result callback."""
    from unittest.mock import AsyncMock, patch
    from petrel.models import MCPServerRecord, Protocol, AuthState

    out_file = tmp_path / "results.jsonl"

    servers = [
        MCPServerRecord(
            url=f"https://server{i}.example.com",
            protocol=Protocol.STREAMABLE_HTTP,
            auth_state=AuthState.NONE,
        )
        for i in range(3)
    ]

    async def _fake_batch(urls, client, concurrency=20, source_map=None, on_result=None):
        for r in servers:
            if on_result:
                on_result(r)
        return servers

    with patch("petrel.cli.crtsh_search", new_callable=AsyncMock,
               return_value=SourceResult(urls=["server0.example.com"])), \
         patch("petrel.cli.hf_spaces_search", new_callable=AsyncMock,
               return_value=SourceResult(urls=[])), \
         patch("petrel.cli.shodan_search", new_callable=AsyncMock, return_value=SourceResult(urls=[])), \
         patch("petrel.cli.registries_search", new_callable=AsyncMock, return_value=SourceResult(urls=[])), \
         patch("petrel.cli.probe_urls_batch", side_effect=_fake_batch):
        result = runner.invoke(app, [
            "discover", "--output", str(out_file),
            "--no-censys", "--no-github", "--no-npm", "--no-smithery", "--no-pypi", "--no-fofa",
            "--no-shodan", "--no-registries",
        ])

    assert result.exit_code == 0, result.output
    assert out_file.exists(), "Output file was not created"
    lines = [ln for ln in out_file.read_text().splitlines() if ln.strip()]
    assert len(lines) == 3, f"Expected 3 records written incrementally, got {len(lines)}"


# ---------------------------------------------------------------------------
# PERF-02: Parallel discovery sources
# ---------------------------------------------------------------------------

def test_perf02_all_sources_invoked(tmp_path: Path):
    """PERF-02: All enabled discovery sources are invoked in a single discover run."""
    from unittest.mock import AsyncMock, patch

    empty = SourceResult(urls=[])
    crt_mock = AsyncMock(return_value=empty)
    hf_mock = AsyncMock(return_value=empty)
    gh_mock = AsyncMock(return_value=empty)
    npm_mock = AsyncMock(return_value=empty)
    sm_mock = AsyncMock(return_value=empty)
    pypi_mock = AsyncMock(return_value=empty)
    reg_mock = AsyncMock(return_value=empty)

    with patch("petrel.cli.crtsh_search", crt_mock), \
         patch("petrel.cli.hf_spaces_search", hf_mock), \
         patch("petrel.cli.github_search", gh_mock), \
         patch("petrel.cli.npm_search", npm_mock), \
         patch("petrel.cli.smithery_search", sm_mock), \
         patch("petrel.cli.pypi_search", pypi_mock), \
         patch("petrel.cli.registries_search", reg_mock):
        runner.invoke(app, [
            "discover", "--no-probe", "--no-censys", "--no-fofa", "--no-shodan",
        ])

    assert crt_mock.called, "crtsh_search was not called"
    assert hf_mock.called, "hf_spaces_search was not called"
    assert gh_mock.called, "github_search was not called"
    assert npm_mock.called, "npm_search was not called"
    assert sm_mock.called, "smithery_search was not called"
    assert pypi_mock.called, "pypi_search was not called"
    assert reg_mock.called, "registries_search was not called"


# ---------------------------------------------------------------------------
# F-03: diff — disappeared servers
# ---------------------------------------------------------------------------

def test_f03_diff_disappeared_servers(tmp_path: Path):
    """F-03: diff shows servers present in old but absent in new as Disappeared."""
    old_path = tmp_path / "old.jsonl"
    new_path = tmp_path / "new.jsonl"

    old_path.write_text(
        json.dumps(_CRITICAL_RECORD) + "\n" +
        json.dumps(_LOW_RECORD)
    )
    # new run only has the LOW record — CRITICAL disappeared
    new_path.write_text(json.dumps(_LOW_RECORD))

    result = runner.invoke(app, [
        "diff", str(old_path), str(new_path), "--min-risk", "LOW",
    ])

    assert result.exit_code == 0, result.output
    assert "Disappeared" in result.output
    assert "critical.example.com" in result.output


# ---------------------------------------------------------------------------
# F-04: diff — new tools in existing servers
# ---------------------------------------------------------------------------

def test_f04_diff_new_tools_in_existing(tmp_path: Path):
    """F-04: diff shows new tools added to a server that exists in both runs."""
    old_path = tmp_path / "old.jsonl"
    new_path = tmp_path / "new.jsonl"

    shared_url = "https://shared.example.com"
    old_rec = dict(
        _LOW_RECORD,
        url=shared_url,
        tools=[{"name": "existing_tool", "risk_tier": "INFO", "schema_risk_params": []}],
    )
    new_rec = dict(
        _LOW_RECORD,
        url=shared_url,
        tools=[
            {"name": "existing_tool", "risk_tier": "INFO", "schema_risk_params": []},
            {"name": "brand_new_tool", "risk_tier": "HIGH", "schema_risk_params": []},
        ],
    )

    old_path.write_text(json.dumps(old_rec))
    new_path.write_text(json.dumps(new_rec))

    result = runner.invoke(app, ["diff", str(old_path), str(new_path)])

    assert result.exit_code == 0, result.output
    assert "brand_new_tool" in result.output
    assert "New Tools" in result.output
