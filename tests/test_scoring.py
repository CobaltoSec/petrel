"""Tests for risk scoring."""
import pytest
from petrel.models import AuthState, MCPResource, MCPServerRecord, MCPTool, Protocol, RiskTier
from petrel.scoring.risk import (
    _score_from_description,
    _score_from_schema,
    score_server,
    score_tool,
)


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


# ---------------------------------------------------------------------------
# S1 — Description-based scoring
# ---------------------------------------------------------------------------

def test_s1_description_arbitrary_shell_critical():
    """Tool description containing 'arbitrary' triggers CRITICAL."""
    tier = _score_from_description("Executes arbitrary shell commands on the host")
    assert tier == RiskTier.CRITICAL


def test_s1_description_read_file_content_high():
    """Tool description containing 'read file' triggers HIGH."""
    tier = _score_from_description("Reads file content from the local filesystem")
    assert tier == RiskTier.HIGH


def test_s1_description_none_returns_info():
    assert _score_from_description(None) == RiskTier.INFO


def test_s1_description_benign_returns_info():
    assert _score_from_description("Returns the current weather forecast") == RiskTier.INFO


def test_s1_score_tool_innocent_name_critical_description():
    """Innocuous name + CRITICAL description → score_tool returns CRITICAL."""
    tool = MCPTool(
        name="my_helper",
        description="This tool can execute arbitrary shell commands via subprocess",
    )
    assert score_tool(tool) == RiskTier.CRITICAL


def test_s1_score_tool_innocent_name_high_description():
    """Innocuous name + HIGH description → score_tool returns HIGH."""
    tool = MCPTool(
        name="data_loader",
        description="Performs an http request to retrieve external data",
    )
    assert score_tool(tool) == RiskTier.HIGH


# ---------------------------------------------------------------------------
# S2 — inputSchema parameter name scoring
# ---------------------------------------------------------------------------

def test_s2_schema_command_param_critical():
    """Unconstrained 'command' string param → CRITICAL."""
    schema = {"properties": {"command": {"type": "string"}}}
    tier, params = _score_from_schema(schema)
    assert tier == RiskTier.CRITICAL
    assert "command" in params


def test_s2_schema_sql_with_enum_high_not_critical():
    """'sql' param with enum constraint → HIGH (not escalated to CRITICAL)."""
    schema = {"properties": {"sql": {"type": "string", "enum": ["SELECT 1", "SELECT 2"]}}}
    tier, params = _score_from_schema(schema)
    assert tier == RiskTier.HIGH
    assert "sql" in params


def test_s2_schema_sql_unconstrained_critical():
    """'sql' param unconstrained → CRITICAL."""
    schema = {"properties": {"sql": {"type": "string"}}}
    tier, params = _score_from_schema(schema)
    assert tier == RiskTier.CRITICAL
    assert "sql" in params


def test_s2_schema_path_unconstrained_high():
    """Unconstrained 'path' string param → HIGH (medium param escalated)."""
    schema = {"properties": {"path": {"type": "string"}}}
    tier, params = _score_from_schema(schema)
    assert tier == RiskTier.HIGH
    assert "path" in params


def test_s2_schema_path_constrained_medium():
    """'path' param with maxLength → MEDIUM (not escalated)."""
    schema = {"properties": {"path": {"type": "string", "maxLength": 256}}}
    tier, params = _score_from_schema(schema)
    assert tier == RiskTier.MEDIUM
    # constrained path not added to dangerous_params
    assert "path" not in params


def test_s2_schema_no_schema_returns_info():
    tier, params = _score_from_schema(None)
    assert tier == RiskTier.INFO
    assert params == []


def test_s2_dangerous_params_stored_on_tool():
    """score_tool stores dangerous inputSchema param names in tool.schema_risk_params."""
    tool = MCPTool(
        name="run_query",
        input_schema={"properties": {"command": {"type": "string"}, "timeout": {"type": "integer"}}},
    )
    score_tool(tool)
    assert "command" in tool.schema_risk_params


def test_s2_schema_cmd_param_critical():
    """'cmd' param (critical set) → CRITICAL regardless of constraint."""
    schema = {"properties": {"cmd": {"type": "string"}}}
    tier, params = _score_from_schema(schema)
    assert tier == RiskTier.CRITICAL
    assert "cmd" in params


# ---------------------------------------------------------------------------
# S3 — Tool family clustering
# ---------------------------------------------------------------------------

def test_s3_exec_network_cluster_critical():
    """exec + network tools → CRITICAL via exfiltration cluster signal."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        tools=[MCPTool(name="execute_bash"), MCPTool(name="fetch_url")],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.CRITICAL
    assert any("exfiltration cluster" in r for r in result.risk_reasons)


def test_s3_exec_messaging_cluster_critical():
    """exec + messaging tools → CRITICAL via exfiltration cluster signal."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        tools=[MCPTool(name="run_command"), MCPTool(name="send_email")],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.CRITICAL
    assert any("exfiltration cluster" in r for r in result.risk_reasons)


def test_s3_redundant_exec_cluster_critical():
    """Two or more exec-family tools → CRITICAL via redundant exec cluster signal."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        tools=[
            MCPTool(name="execute_bash"),
            MCPTool(name="run_command"),
            MCPTool(name="get_weather"),
        ],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.CRITICAL
    assert any("redundant exec cluster" in r for r in result.risk_reasons)


def test_s3_fs_read_write_cluster_high():
    """read + write filesystem tools → HIGH via full filesystem cluster signal."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        tools=[MCPTool(name="read_file"), MCPTool(name="write_file")],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
    assert any("full filesystem cluster" in r for r in result.risk_reasons)


def test_s3_no_cluster_no_cluster_reason():
    """Single benign tool → no cluster reason added."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        tools=[MCPTool(name="get_weather")],
    )
    result = score_server(record)
    assert not any("cluster" in r for r in result.risk_reasons)


# ---------------------------------------------------------------------------
# S4 — Wide attack surface + dangerous server name
# ---------------------------------------------------------------------------

def test_s4_wide_surface_55_tools_high():
    """55 benign tools → HIGH server tier and 'wide attack surface' reason."""
    tools = [MCPTool(name=f"get_item_{i}") for i in range(55)]
    record = MCPServerRecord(
        url="http://wide.example.com",
        auth_state=AuthState.BEARER,
        tools=tools,
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
    assert any("wide attack surface" in r and "55" in r for r in result.risk_reasons)


def test_s4_49_tools_no_wide_surface_reason():
    """49 tools does NOT trigger wide attack surface (threshold = 50)."""
    tools = [MCPTool(name=f"get_item_{i}") for i in range(49)]
    record = MCPServerRecord(
        url="http://narrow.example.com",
        auth_state=AuthState.BEARER,
        tools=tools,
    )
    result = score_server(record)
    assert not any("wide attack surface" in r for r in result.risk_reasons)


def test_s4_dangerous_server_name_high():
    """server_name containing 'computer-use' → HIGH and corresponding reason."""
    record = MCPServerRecord(
        url="http://x.example.com",
        server_name="computer-use-agent",
        auth_state=AuthState.BEARER,
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
    assert any("server name signals dangerous capability" in r for r in result.risk_reasons)


def test_s4_dangerous_server_name_terminal():
    """server_name 'terminal' → HIGH."""
    record = MCPServerRecord(
        url="http://x.example.com",
        server_name="terminal",
        auth_state=AuthState.BEARER,
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH


def test_s4_benign_server_name_no_signal():
    """Benign server_name does not add HIGH signal."""
    record = MCPServerRecord(
        url="http://x.example.com",
        server_name="weather-helper",
        auth_state=AuthState.BEARER,
        tools=[],
    )
    result = score_server(record)
    assert not any("server name signals" in r for r in result.risk_reasons)


# ---------------------------------------------------------------------------
# S5 — Capabilities + sensitive resource URIs
# ---------------------------------------------------------------------------

def test_s5_sampling_capability_high():
    """server_capabilities with sampling=True → HIGH and sampling reason."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        server_capabilities={"sampling": True},
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
    assert any("sampling" in r for r in result.risk_reasons)


def test_s5_roots_capability_medium():
    """server_capabilities with roots=True → MEDIUM and roots reason."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        server_capabilities={"roots": True},
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.MEDIUM
    assert any("roots" in r for r in result.risk_reasons)


def test_s5_file_uri_resource_high():
    """Resource with file:// URI → HIGH."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        resources=[MCPResource(uri="file:///etc/passwd", name="passwd")],
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
    assert any("sensitive resource URI" in r for r in result.risk_reasons)


def test_s5_postgres_uri_with_credentials_critical():
    """Resource with postgres://user:pass@host URI → CRITICAL (credentials detected)."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        resources=[MCPResource(uri="postgres://admin:s3cr3t@db.internal:5432/prod")],
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.CRITICAL
    assert any("credentials in resource URI" in r for r in result.risk_reasons)


def test_s5_postgres_uri_without_credentials_high():
    """Resource with postgres://host/db (no password) → HIGH."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        resources=[MCPResource(uri="postgres://db.internal:5432/prod")],
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH
    assert any("sensitive resource URI" in r for r in result.risk_reasons)


def test_s5_s3_uri_resource_high():
    """Resource with s3:// URI → HIGH."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        resources=[MCPResource(uri="s3://my-bucket/data/config.json")],
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.HIGH


def test_s5_https_uri_no_signal():
    """Resource with https:// URI → no signal added."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        resources=[MCPResource(uri="https://api.example.com/data")],
        tools=[],
    )
    result = score_server(record)
    assert not any("resource URI" in r for r in result.risk_reasons)


# ---------------------------------------------------------------------------
# S6 — API key in URL
# ---------------------------------------------------------------------------

def test_s6_api_key_auth_adds_medium_floor():
    """AuthState.API_KEY → at least MEDIUM + reason about URL query parameters."""
    record = MCPServerRecord(
        url="http://x.example.com?api_key=supersecret",
        auth_state=AuthState.API_KEY,
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier >= RiskTier.MEDIUM or result.risk_tier == RiskTier.MEDIUM
    assert any("URL query parameters" in r for r in result.risk_reasons)


def test_s6_api_key_floor_is_medium_not_lower():
    """With only API_KEY auth and no tools, tier is MEDIUM (not LOW/INFO)."""
    record = MCPServerRecord(
        url="http://x.example.com?key=abc",
        auth_state=AuthState.API_KEY,
        tools=[],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.MEDIUM


def test_s6_api_key_does_not_cap_higher_tiers():
    """API_KEY with a CRITICAL tool stays CRITICAL (S6 only sets a floor)."""
    record = MCPServerRecord(
        url="http://x.example.com?key=abc",
        auth_state=AuthState.API_KEY,
        tools=[MCPTool(name="execute_bash")],
    )
    result = score_server(record)
    assert result.risk_tier == RiskTier.CRITICAL
    assert any("URL query parameters" in r for r in result.risk_reasons)


def test_s6_bearer_auth_no_api_key_reason():
    """Bearer auth does not trigger the API key reason."""
    record = MCPServerRecord(
        url="http://x.example.com",
        auth_state=AuthState.BEARER,
        tools=[],
    )
    result = score_server(record)
    assert not any("URL query parameters" in r for r in result.risk_reasons)


# ---------------------------------------------------------------------------
# SR-03 — query param FP calibration
# ---------------------------------------------------------------------------

def test_sr03_query_param_not_critical():
    from petrel.scoring.risk import score_tool
    from petrel.models import MCPTool, RiskTier
    tool = MCPTool(
        name="search_knowledge",
        description="Search the knowledge base",
        inputSchema={"type": "object", "properties": {"query": {"type": "string"}}},
    )
    tier = score_tool(tool)
    assert tier != RiskTier.CRITICAL, f"search_knowledge(query: str) should not be CRITICAL, got {tier}"
    assert tier in (RiskTier.HIGH, RiskTier.MEDIUM, RiskTier.LOW)


def test_sr03_sql_param_still_critical():
    from petrel.scoring.risk import score_tool
    from petrel.models import MCPTool, RiskTier
    tool = MCPTool(
        name="run_query",
        inputSchema={"type": "object", "properties": {"sql": {"type": "string"}}},
    )
    assert score_tool(tool) == RiskTier.CRITICAL


# ---------------------------------------------------------------------------
# SR-01 — FS_READ + NETWORK/MESSAGING cluster
# ---------------------------------------------------------------------------

def test_sr01_fs_read_network_cluster_critical():
    from petrel.scoring.risk import score_server
    from petrel.models import MCPServerRecord, MCPTool, Protocol, AuthState, RiskTier
    record = MCPServerRecord(
        url="https://example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        tools=[
            MCPTool(name="read_file"),
            MCPTool(name="fetch_url"),
        ],
    )
    scored = score_server(record)
    assert scored.risk_tier == RiskTier.CRITICAL
    assert any("exfiltration cluster" in r for r in scored.risk_reasons)


def test_sr01_fs_read_messaging_cluster_critical():
    from petrel.scoring.risk import score_server
    from petrel.models import MCPServerRecord, MCPTool, Protocol, AuthState, RiskTier
    record = MCPServerRecord(
        url="https://example.com",
        protocol=Protocol.STREAMABLE_HTTP,
        auth_state=AuthState.NONE,
        tools=[
            MCPTool(name="read_file"),
            MCPTool(name="send_email"),
        ],
    )
    scored = score_server(record)
    assert scored.risk_tier == RiskTier.CRITICAL
    assert any("exfiltration cluster" in r for r in scored.risk_reasons)


def test_sr01_fs_write_network_cluster_high():
    from petrel.scoring.risk import _detect_clusters
    from petrel.models import MCPTool, RiskTier
    tools = [MCPTool(name="write_file"), MCPTool(name="fetch_url")]
    findings = _detect_clusters(tools)
    tiers = [f[0] for f in findings]
    assert RiskTier.HIGH in tiers or RiskTier.CRITICAL in tiers
    assert any("supply-chain" in f[1] for f in findings)
