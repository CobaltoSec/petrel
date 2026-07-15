"""Risk scoring for MCP tools and servers."""
from __future__ import annotations

from ..models import AuthState, MCPServerRecord, MCPTool, RiskTier, worst_tier

# Unauthenticated access to these = CRITICAL
# Short/ambiguous names (exact match only — "exec" would false-positive on "execute_sql")
_CRITICAL_EXACT = {
    "bash", "shell", "exec", "terminal", "cmd",
}
# Longer patterns — safe for substring matching
_CRITICAL_PATTERNS = {
    "execute_bash", "execute_command", "run_command",
    "run_script", "execute_script",
    "run_python", "execute_python", "python_repl", "code_exec",
    "subprocess_run", "system_exec",
}

# Dangerous but needs context
_HIGH_PATTERNS = {
    "execute_sql", "run_query", "db_execute", "sql_query",
    "write_file", "create_file", "delete_file", "move_file", "overwrite_file",
    "git_commit", "git_push", "git_force_push", "deploy",
    "send_email", "send_message", "post_slack",
}

# Potentially sensitive depending on scope
_MEDIUM_PATTERNS = {
    "read_file", "get_file", "list_directory", "list_files", "ls",
    "fetch_url", "http_request", "web_request", "get_webpage", "curl",
    "search_files", "grep_files",
}


def score_tool(tool: MCPTool) -> RiskTier:
    name = tool.name.lower()
    if name in _CRITICAL_EXACT or name in _CRITICAL_PATTERNS or any(p in name for p in _CRITICAL_PATTERNS):
        return RiskTier.CRITICAL
    if name in _HIGH_PATTERNS or any(p in name for p in _HIGH_PATTERNS):
        return RiskTier.HIGH
    if name in _MEDIUM_PATTERNS or any(p in name for p in _MEDIUM_PATTERNS):
        return RiskTier.MEDIUM
    return RiskTier.LOW


def score_server(record: MCPServerRecord) -> MCPServerRecord:
    scored_tools = []
    for tool in record.tools:
        t = tool.model_copy()
        t.risk_tier = score_tool(tool)
        scored_tools.append(t)
    record.tools = scored_tools

    reasons: list[str] = []
    server_tier = RiskTier.INFO

    for tool in scored_tools:
        if tool.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM):
            server_tier = worst_tier(server_tier, tool.risk_tier)
            if tool.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
                reasons.append(f"tool '{tool.name}' ({tool.risk_tier})")

    if record.auth_state == AuthState.NONE:
        if server_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
            # No auth + dangerous tool = escalate HIGH → CRITICAL
            server_tier = RiskTier.CRITICAL
            reasons.insert(0, "no authentication")
        elif server_tier == RiskTier.MEDIUM:
            server_tier = RiskTier.HIGH
            reasons.insert(0, "no authentication")
        else:
            server_tier = RiskTier.LOW
            reasons.append("no authentication")
    elif record.auth_state == AuthState.REQUIRED and not record.tools:
        server_tier = RiskTier.INFO

    record.risk_tier = server_tier
    record.risk_reasons = reasons
    return record
