"""Tests for Petrel data models."""
import pytest
from petrel.models import (
    AuthState,
    MCPPrompt,
    MCPPromptArgument,
    MCPResource,
    MCPServerRecord,
    MCPTool,
    Platform,
    Protocol,
    RiskTier,
    worst_tier,
)


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


# --- v0.5.0 additions ---


def test_worst_tier_three_args():
    assert worst_tier(RiskTier.HIGH, RiskTier.LOW, RiskTier.CRITICAL) == RiskTier.CRITICAL


def test_worst_tier_single_arg():
    assert worst_tier(RiskTier.MEDIUM) == RiskTier.MEDIUM


def test_mcp_resource_creation():
    r = MCPResource(uri="file:///data/db", name="database", mimeType="application/json")
    assert r.uri == "file:///data/db"
    assert r.name == "database"
    assert r.mime_type == "application/json"


def test_mcp_resource_mime_alias():
    r = MCPResource(uri="x://y", mimeType="text/plain")
    assert r.mime_type == "text/plain"


def test_mcp_resource_defaults():
    r = MCPResource(uri="x://y")
    assert r.name is None
    assert r.description is None
    assert r.mime_type is None


def test_mcp_prompt_with_arguments():
    arg = MCPPromptArgument(name="topic", description="Topic to summarize", required=True)
    prompt = MCPPrompt(name="summarize", description="Summarize a topic", arguments=[arg])
    assert prompt.name == "summarize"
    assert len(prompt.arguments) == 1
    assert prompt.arguments[0].required is True


def test_mcp_prompt_defaults():
    prompt = MCPPrompt(name="hello")
    assert prompt.description is None
    assert prompt.arguments == []


def test_mcp_tool_schema_risk_params_default():
    tool = MCPTool(name="read_file")
    assert tool.schema_risk_params == []


def test_mcp_tool_schema_risk_params_set():
    tool = MCPTool(name="exec", schema_risk_params=["command", "args"])
    assert "command" in tool.schema_risk_params


def test_server_record_new_field_defaults():
    r = MCPServerRecord(url="http://example.com")
    assert r.endpoint_path is None
    assert r.server_capabilities == {}
    assert r.server_instructions is None
    assert r.final_url is None
    assert r.redirect_count == 0
    assert r.resources == []
    assert r.prompts == []
    assert r.platform == Platform.UNKNOWN


def test_server_record_platform_field():
    r = MCPServerRecord(url="http://example.com", platform=Platform.HUGGINGFACE)
    assert r.platform == Platform.HUGGINGFACE


def test_platform_enum_values():
    assert Platform.HUGGINGFACE == "huggingface"
    assert Platform.VERCEL == "vercel"
    assert Platform.RAILWAY == "railway"
    assert Platform.FLY == "fly.io"
    assert Platform.AWS_LAMBDA == "aws-lambda"
    assert Platform.GCP == "gcp"
    assert Platform.AZURE == "azure"
    assert Platform.CLOUDFLARE_WORKERS == "cloudflare-workers"
    assert Platform.RENDER == "render"
    assert Platform.UNKNOWN == "unknown"
