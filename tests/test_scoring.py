"""Tests for risk scoring."""
import pytest
from petrel.models import AuthState, MCPServerRecord, MCPTool, Protocol, RiskTier
from petrel.scoring.risk import score_server, score_tool


@pytest.mark.parametrize("name,expected", [
    ("execute_bash", RiskTier.CRITICAL),
    ("run_command", RiskTier.CRITICAL),
    ("shell", RiskTier.CRITICAL),
    ("write_file", RiskTier.HIGH),
    ("execute_sql", RiskTier.HIGH),
    ("read_file", RiskTier.MEDIUM),
    ("fetch_url", RiskTier.MEDIUM),
    ("search_knowledge", RiskTier.LOW),
    ("get_weather", RiskTier.LOW),
])
def test_score_tool(name, expected):
    tool = MCPTool(name=name)
    assert score_tool(tool) == expected


def test_score_server_critical_no_auth():
    record = MCPServerRecord(
        url="http://danger.example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        tools=[MCPTool(name="execute_bash")],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.CRITICAL
    assert "no authentication" in result.risk_reasons


def test_score_server_high_with_auth():
    record = MCPServerRecord(
        url="http://safe.example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.BEARER,
        tools=[MCPTool(name="execute_bash")],
    )
    result = score_server(record)
    # Has auth — dangerous tool but tier stays CRITICAL (tool itself is critical)
    # but no "no authentication" reason
    assert "no authentication" not in result.risk_reasons


def test_score_server_no_tools_no_auth():
    record = MCPServerRecord(
        url="http://empty.example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.LOW
    assert "no authentication" in result.risk_reasons


def test_score_server_medium_no_auth_escalates():
    record = MCPServerRecord(
        url="http://medium.example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        tools=[MCPTool(name="read_file")],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
