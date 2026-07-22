"""Risk scoring for MCP tools and servers."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import AuthState, MCPServerRecord, MCPTool, Platform, Protocol, RiskTier, worst_tier

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
_SCHEMA_HIGH_PARAMS = frozenset(["code", "script", "payload", "expression", "sql", "program"])
_SCHEMA_MEDIUM_PARAMS = frozenset(["path", "filename", "filepath", "file_path", "template", "url", "uri", "query"])


def _is_unconstrained_string(prop_schema: dict) -> bool:
    if not isinstance(prop_schema, dict):
        return False
    if prop_schema.get("type") != "string":
        return False
    return not any(k in prop_schema for k in ("pattern", "enum", "minLength", "maxLength", "format"))


def _score_from_schema(schema: dict | None, _depth: int = 0) -> tuple[RiskTier, list[str]]:
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
        # Recurse into nested object schemas (cap at depth 3, skip $ref)
        if (
            _depth < 3
            and isinstance(prop_schema, dict)
            and prop_schema.get("type") == "object"
            and "properties" in prop_schema
            and "$ref" not in prop_schema
        ):
            nested_tier, nested_params = _score_from_schema(prop_schema, _depth + 1)
            tier = worst_tier(tier, nested_tier)
            dangerous_params.extend(nested_params)
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
    # SR-09: tools individually scored CRITICAL count as implicit exec-family
    critical_names = {t.name.lower() for t in tools if t.risk_tier == RiskTier.CRITICAL}
    findings: list[tuple[RiskTier, str]] = []
    exec_hits = sorted((names & _FAMILY_CODE_EXEC) | critical_names)
    net_hits = sorted(names & _FAMILY_NETWORK)
    msg_hits = sorted(names & _FAMILY_MESSAGING)
    fs_read_hits = sorted(names & _FAMILY_FS_READ)
    fs_write_hits = sorted(names & _FAMILY_FS_WRITE)
    if exec_hits and net_hits:
        findings.append((RiskTier.CRITICAL, f"exfiltration cluster: exec={exec_hits} + network={net_hits}"))
    if exec_hits and msg_hits:
        findings.append((RiskTier.CRITICAL, f"exfiltration cluster: exec={exec_hits} + messaging={msg_hits}"))
    if fs_read_hits and net_hits:
        findings.append((RiskTier.CRITICAL, f"exfiltration cluster: read={fs_read_hits} + network={net_hits}"))
    if fs_read_hits and msg_hits:
        findings.append((RiskTier.CRITICAL, f"exfiltration cluster: read={fs_read_hits} + messaging={msg_hits}"))
    if fs_write_hits and net_hits:
        findings.append((RiskTier.HIGH, f"supply-chain cluster: write={fs_write_hits} + network={net_hits}"))
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
# SR-07 — server_instructions injection / credential leak scoring
# ---------------------------------------------------------------------------
_INJECT_PATTERNS = frozenset([
    "ignore previous", "disregard instructions", "system prompt", "you are now",
    "forget your", "new persona", "act as", "jailbreak",
])
_CRED_KEYWORDS = frozenset(["password", "api_key", "secret", "token", "credentials"])


def _score_server_instructions(text: str | None) -> tuple[RiskTier, list[str]]:
    if not text or not text.strip():
        return RiskTier.INFO, []
    text_lower = text.lower()
    tier = RiskTier.INFO
    reasons: list[str] = []
    # CRITICAL: injection patterns (substring match)
    matched_inject = [p for p in _INJECT_PATTERNS if p in text_lower]
    if matched_inject:
        tier = worst_tier(tier, RiskTier.CRITICAL)
        reasons.append(f"server_instructions injection pattern(s): {sorted(matched_inject)}")
    # HIGH: credential keyword followed by = or : with a non-whitespace value
    for keyword in _CRED_KEYWORDS:
        if re.search(rf'\b{re.escape(keyword)}\s*[=:]\s*\S+', text_lower):
            tier = worst_tier(tier, RiskTier.HIGH)
            reasons.append(f"potential credential leak in server_instructions: '{keyword}'")
    return tier, reasons


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
    # capability_tier: from tool danger scores, clustering, capabilities, and resources.
    # Represents actual dangerous capabilities present on the server.
    capability_tier = RiskTier.INFO
    # structural_tier: from wide surface count and dangerous server name.
    # Represents structural signals only — not proof of dangerous capability.
    structural_tier = RiskTier.INFO

    # 2. Aggregate tool tiers → capability
    for tool in scored_tools:
        if tool.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM):
            capability_tier = worst_tier(capability_tier, tool.risk_tier)
            if tool.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
                reasons.append(f"tool '{tool.name}' ({tool.risk_tier})")

    # 3. Tool clustering (S3) → capability
    for tier, reason in _detect_clusters(scored_tools):
        capability_tier = worst_tier(capability_tier, tier)
        reasons.append(reason)

    # 4. Wide attack surface + dangerous server name (S4) → structural only
    tool_count = len(scored_tools)
    if tool_count >= _WIDE_SURFACE_THRESHOLD:
        structural_tier = worst_tier(structural_tier, RiskTier.HIGH)
        reasons.append(f"wide attack surface ({tool_count} tools)")
    if record.server_name:
        sn = record.server_name.lower()
        if any(p in sn for p in _DANGEROUS_SERVER_NAMES):
            structural_tier = worst_tier(structural_tier, RiskTier.HIGH)
            reasons.append(f"server name signals dangerous capability: '{record.server_name}'")

    # 5. Capabilities scoring (S5a) → capability
    for tier, reason in _score_capabilities(record.server_capabilities):
        capability_tier = worst_tier(capability_tier, tier)
        reasons.append(reason)

    # 6. Resource URI scoring (S5b) → capability
    for tier, reason in _score_resources(record.resources):
        capability_tier = worst_tier(capability_tier, tier)
        reasons.append(reason)

    # SR-06: sampling + FS_READ tools → autonomous exfiltration → CRITICAL.
    # An LLM with sampling can initiate outbound calls; paired with filesystem read
    # tools it can exfiltrate data entirely without human intervention.
    tool_names_lower = {t.name.lower() for t in scored_tools}
    if record.server_capabilities.get("sampling") and (tool_names_lower & _FAMILY_FS_READ):
        capability_tier = worst_tier(capability_tier, RiskTier.CRITICAL)
        reasons.append("autonomous exfiltration: sampling + filesystem read")

    # SR-07: server_instructions injection / credential leak → capability
    si_tier, si_reasons = _score_server_instructions(record.server_instructions)
    if si_tier != RiskTier.INFO:
        capability_tier = worst_tier(capability_tier, si_tier)
        reasons.extend(si_reasons)

    # Combined server tier: both capability and structural signals contribute.
    server_tier = worst_tier(capability_tier, structural_tier)

    # 7. Auth escalation: HIGH→CRITICAL only when capability_tier is HIGH/CRITICAL.
    #    Wide-surface structural signals alone do NOT warrant CRITICAL escalation —
    #    50 read_file tools with no auth is HIGH, not the same as execute_bash + no auth.
    if record.auth_state == AuthState.NONE:
        if capability_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
            server_tier = RiskTier.CRITICAL
            reasons.insert(0, "no authentication")
        elif server_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
            # Only structural HIGH (wide surface / dangerous name, benign tools):
            # server_tier is already HIGH from structural; keep it, don't escalate to CRITICAL.
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

    # SR-10: anonymous server signal
    if (not record.server_name
            and not record.tools
            and record.auth_state == AuthState.NONE
            and record.protocol != Protocol.UNKNOWN):
        reasons.append("anonymous server: no name, no tools, no auth")

    record.risk_tier = server_tier
    record.risk_reasons = reasons

    # SR-08: Numeric priority score 0-100
    _TIER_BASE = {"CRITICAL": 80, "HIGH": 60, "MEDIUM": 40, "LOW": 20, "INFO": 0}
    base = _TIER_BASE.get(
        record.risk_tier.value if hasattr(record.risk_tier, "value") else str(record.risk_tier), 0
    )
    bonus = 0
    # +15 if no auth and tier >= HIGH
    if record.auth_state == AuthState.NONE and base >= 60:
        bonus += 15
    # +5 if any tool has exec signal
    if tool_names_lower & _FAMILY_CODE_EXEC:
        bonus += 5
    # +3 if platform is Railway/Fly/HuggingFace/Vercel
    if record.platform in (Platform.RAILWAY, Platform.FLY, Platform.HUGGINGFACE, Platform.VERCEL):
        bonus += 3
    record.priority_score = min(100, base + bonus)

    return record
