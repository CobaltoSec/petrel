"""Tests for Petrel data models."""
import pytest
from petrel.models import AuthState, MCPServerRecord, MCPTool, Protocol, RiskTier, worst_tier


def test_worst_tier_ordering():
    assert worst_tier(RiskTier.CRITICAL, RiskTier.HIGH) == RiskTier.CRITICAL
    assert worst_tier(RiskTier.LOW, RiskTier.MEDIUM) == RiskTier.MEDIUM
    assert worst_tier(RiskTier.INFO, RiskTier.INFO) == RiskTier.INFO


def test_server_record_defaults():
    r = MCPServerRecord(url="http://example.com")
    assert r.protocol == Protocol.UNKNOWN
    assert r.auth_state == AuthState.UNKNOWN
    assert r.tools == []
    assert not r.is_confirmed_mcp
    assert not r.has_auth


def test_server_record_confirmed():
    r = MCPServerRecord(url="http://example.com", protocol=Protocol.STREAMABLE_HTTP)
    assert r.is_confirmed_mcp


def test_has_auth():
    r = MCPServerRecord(url="http://x.com", auth_state=AuthState.BEARER)
    assert r.has_auth

    r2 = MCPServerRecord(url="http://x.com", auth_state=AuthState.NONE)
    assert not r2.has_auth


def test_mcp_tool_alias():
    tool = MCPTool(name="execute_bash", inputSchema={"type": "object"})
    assert tool.input_schema == {"type": "object"}
