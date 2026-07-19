"""Risk scoring for MCP tools and servers."""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import AuthState, MCPServerRecord, MCPTool, RiskTier, worst_tier

# ---------------------------------------------------------------------------
# S1 — Description-based phrases
# ---------------------------------------------------------------------------
_DESC_CRITICAL_PHRASES = frozenset([
    "arbitrary", "any command", "shell command", "system command",
    "execute code", "subprocess", "os.system", "eval(", "exec(",
    "arbitrary shell", "arbitrary command", "run any", "execute any",
    "shell access", "command line", "arbitrary python", "arbitrary script",
    "spawn process", "popen",
])
_DESC_HIGH_PHRASES = frozenset([
    "write to file", "create file", "delete file", "modify file",
    "database query", "sql query", "send email", "send message",
    "http request", "web request", "fetch url",
    "read file", "file content", "file system",
])


def _score_from_description(desc: str | None) -> RiskTier:
    if not desc:
        return RiskTier.INFO
    d = desc.lower()
    if any(p in d for p in _DESC_CRITICAL_PHRASES):
        return RiskTier.CRITICAL
    if any(p in d for p in _DESC_HIGH_PHRASES):
        return RiskTier.HIGH
    return RiskTier.INFO


# ---------------------------------------------------------------------------
# S2 — inputSchema parameter name scoring
# ---------------------------------------------------------------------------
_SCHEMA_CRITICAL_PARAMS = frozenset(["command", "cmd", "shell", "bash", "exec", "evaluate"])
_SCHEMA_HIGH_PARAMS = frozenset(["code", "script", "payload", "expression", "query", "sql", "program"])
_SCHEMA_MEDIUM_PARAMS = frozenset(["path", "filename", "filepath", "file_path", "template", "url", "uri"])


def _is_unconstrained_string(prop_schema: dict) -> bool:
    if not isinstance(prop_schema, dict):
        return False
    if prop_schema.get("type") != "string":
        return False
    return not any(k in prop_schema for k in ("pattern", "enum", "minLength", "maxLength", "format"))


def _score_from_schema(schema: dict | None) -> tuple[RiskTier, list[str]]:
    if not schema:
        return RiskTier.INFO, []
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return RiskTier.INFO, []
    tier = RiskTier.INFO
    dangerous_params: list[str] = []
    for param_name, prop_schema in props.items():
        n = param_name.lower()
        unconstrained = _is_unconstrained_string(prop_schema)
        if n in _SCHEMA_CRITICAL_PARAMS:
            tier = worst_tier(tier, RiskTier.CRITICAL)
            dangerous_params.append(param_name)
        elif n in _SCHEMA_HIGH_PARAMS:
            tier = worst_tier(tier, RiskTier.CRITICAL if unconstrained else RiskTier.HIGH)
            dangerous_params.append(param_name)
        elif n in _SCHEMA_MEDIUM_PARAMS:
            tier = worst_tier(tier, RiskTier.HIGH if unconstrained else RiskTier.MEDIUM)
            if unconstrained:
                dangerous_params.append(param_name)
    return tier, dangerous_params


# ---------------------------------------------------------------------------
# S3 — Tool family clustering
# ---------------------------------------------------------------------------
_FAMILY_CODE_EXEC = frozenset([
    "execute_bash", "execute_command", "run_command", "run_script",
    "execute_script", "run_python", "execute_python", "python_repl",
    "code_exec", "subprocess_run", "system_exec", "bash", "shell",
])
_FAMILY_FS_READ = frozenset([
    "read_file", "get_file", "list_directory", "list_files", "ls",
    "search_files", "grep_files",
])
_FAMILY_FS_WRITE = frozenset([
    "write_file", "create_file", "delete_file", "move_file", "overwrite_file",
])
_FAMILY_NETWORK = frozenset([
    "fetch_url", "http_request", "web_request", "get_webpage", "curl",
])
_FAMILY_MESSAGING = frozenset([
    "send_email", "send_message", "post_slack", "send_notification",
])


def _detect_clusters(tools: list) -> list[tuple[RiskTier, str]]:
    names = {t.name.lower() for t in tools}
    findings: list[tuple[RiskTier, str]] = []
    exec_hits = sorted(names & _FAMILY_CODE_EXEC)
    net_hits = sorted(names & _FAMILY_NETWORK)
    msg_hits = sorted(names & _FAMILY_MESSAGING)
    fs_read_hits = sorted(names & _FAMILY_FS_READ)
    fs_write_hits = sorted(names & _FAMILY_FS_WRITE)
    if exec_hits and net_hits:
        findings.append((RiskTier.CRITICAL, f"exfiltration cluster: exec={exec_hits} + network={net_hits}"))
    if exec_hits and msg_hits:
        findings.append((RiskTier.CRITICAL, f"exfiltration cluster: exec={exec_hits} + messaging={msg_hits}"))
    if len(exec_hits) >= 2:
        findings.append((RiskTier.CRITICAL, f"redundant exec cluster: {exec_hits}"))
    if fs_read_hits and fs_write_hits:
        findings.append((RiskTier.HIGH, f"full filesystem cluster: read={fs_read_hits} + write={fs_write_hits}"))
    return findings


# ---------------------------------------------------------------------------
# S4 — Wide attack surface + dangerous server name
# ---------------------------------------------------------------------------
_WIDE_SURFACE_THRESHOLD = 50
_DANGEROUS_SERVER_NAMES = frozenset([
    "computer-use", "computer_use", "computer use",
    "code-interpreter", "code_interpreter", "code interpreter",
    "terminal", "sandbox", "desktop", "operator",
    "code executor", "code-executor",
])


# ---------------------------------------------------------------------------
# S5 — Capabilities + sensitive resource URIs
# ---------------------------------------------------------------------------
_SENSITIVE_URI_SCHEMES = (
    "file://", "postgres://", "postgresql://", "mysql://",
    "redis://", "mongodb://", "sqlite://", "s3://", "gcs://",
)


def _score_capabilities(caps: dict) -> list[tuple[RiskTier, str]]:
    findings: list[tuple[RiskTier, str]] = []
    if caps.get("sampling"):
        findings.append((RiskTier.HIGH, "server declares sampling (can initiate outbound LLM calls)"))
    if caps.get("roots"):
        findings.append((RiskTier.MEDIUM, "server declares roots (filesystem path access)"))
    return findings


def _score_resources(resources: list) -> list[tuple[RiskTier, str]]:
    findings: list[tuple[RiskTier, str]] = []
    for r in resources:
        uri = getattr(r, "uri", "")
        if any(uri.startswith(s) for s in _SENSITIVE_URI_SCHEMES):
            parsed = urlparse(uri)
            if parsed.password:
                findings.append((
                    RiskTier.CRITICAL,
                    f"credentials in resource URI: {parsed.scheme}://...@{parsed.hostname}",
                ))
            else:
                findings.append((RiskTier.HIGH, f"sensitive resource URI: {uri[:80]}"))
    return findings


# ---------------------------------------------------------------------------
# Name-based scoring (original logic, extracted)
# ---------------------------------------------------------------------------
_CRITICAL_EXACT = {"bash", "shell", "exec", "terminal", "cmd"}
_CRITICAL_PATTERNS = {
    "execute_bash", "execute_command", "run_command",
    "run_script", "execute_script",
    "run_python", "execute_python", "python_repl", "code_exec",
    "subprocess_run", "system_exec",
}
_HIGH_PATTERNS = {
    "execute_sql", "run_query", "db_execute", "sql_query",
    "write_file", "create_file", "delete_file", "move_file", "overwrite_file",
    "git_commit", "git_push", "git_force_push", "deploy",
    "send_email", "send_message", "post_slack",
}
_MEDIUM_PATTERNS = {
    "read_file", "get_file", "list_directory", "list_files", "ls",
    "fetch_url", "http_request", "web_request", "get_webpage", "curl",
    "search_files", "grep_files",
}


def _score_from_name(name: str) -> RiskTier:
    n = name.lower()
    if n in _CRITICAL_EXACT or n in _CRITICAL_PATTERNS or any(p in n for p in _CRITICAL_PATTERNS):
        return RiskTier.CRITICAL
    if n in _HIGH_PATTERNS or any(p in n for p in _HIGH_PATTERNS):
        return RiskTier.HIGH
    if n in _MEDIUM_PATTERNS or any(p in n for p in _MEDIUM_PATTERNS):
        return RiskTier.MEDIUM
    return RiskTier.LOW


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_tool(tool: MCPTool) -> RiskTier:
    schema_tier, dangerous_params = _score_from_schema(tool.input_schema)
    if dangerous_params:
        tool.schema_risk_params = dangerous_params
    return worst_tier(
        _score_from_name(tool.name),
        _score_from_description(tool.description),
        schema_tier,
    )


def score_server(record: MCPServerRecord) -> MCPServerRecord:
    # 1. Score each tool (name + description + schema)
    scored_tools = []
    for tool in record.tools:
        t = tool.model_copy()
        t.risk_tier = score_tool(t)
        scored_tools.append(t)
    record.tools = scored_tools

    reasons: list[str] = []
    server_tier = RiskTier.INFO

    # 2. Aggregate tool tiers
    for tool in scored_tools:
        if tool.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM):
            server_tier = worst_tier(server_tier, tool.risk_tier)
            if tool.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
                reasons.append(f"tool '{tool.name}' ({tool.risk_tier})")

    # 3. Tool clustering (S3)
    for tier, reason in _detect_clusters(scored_tools):
        server_tier = worst_tier(server_tier, tier)
        reasons.append(reason)

    # 4. Wide attack surface + dangerous server name (S4)
    tool_count = len(scored_tools)
    if tool_count >= _WIDE_SURFACE_THRESHOLD:
        server_tier = worst_tier(server_tier, RiskTier.HIGH)
        reasons.append(f"wide attack surface ({tool_count} tools)")
    if record.server_name:
        sn = record.server_name.lower()
        if any(p in sn for p in _DANGEROUS_SERVER_NAMES):
            server_tier = worst_tier(server_tier, RiskTier.HIGH)
            reasons.append(f"server name signals dangerous capability: '{record.server_name}'")

    # 5. Capabilities scoring (S5a)
    for tier, reason in _score_capabilities(record.server_capabilities):
        server_tier = worst_tier(server_tier, tier)
        reasons.append(reason)

    # 6. Resource URI scoring (S5b)
    for tier, reason in _score_resources(record.resources):
        server_tier = worst_tier(server_tier, tier)
        reasons.append(reason)

    # 7. Auth escalation (existing logic)
    if record.auth_state == AuthState.NONE:
        if server_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
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

    # 8. API key in URL (S6)
    if record.auth_state == AuthState.API_KEY:
        server_tier = worst_tier(server_tier, RiskTier.MEDIUM)
        reasons.append("API key exposed in URL query parameters (visible in logs/proxies)")

    record.risk_tier = server_tier
    record.risk_reasons = reasons
    return record
