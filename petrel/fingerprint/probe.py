"""MCP server fingerprinting — SSE legacy and Streamable HTTP."""
from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

from ..models import (
    AuthState,
    MCPPrompt,
    MCPPromptArgument,
    MCPResource,
    MCPServerRecord,
    MCPTool,
    Platform,
    Protocol,
)

_STREAMABLE_PATHS = ["/mcp", "/", "/api/mcp", "/api", "/v1/mcp"]
_SSE_PATHS = ["/sse", "/api/sse", "/mcp/sse", "/events"]

_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": "petrel", "version": "0.1.0"},
        "capabilities": {},
    },
}
_TOOLS_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
_TOOLS_LIST_CURSOR = lambda cursor: {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": cursor}}  # noqa: E731
_RESOURCES_LIST = {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}

_SSE_PATH_RE = re.compile(r'data:\s*(/[^\s]+)')
_PROMPTS_LIST = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}}

_URL_AUTH_PARAMS = frozenset([
    "api_key", "apikey", "token", "access_token", "key", "auth", "secret", "api-key",
])


def _has_url_auth(url: str) -> bool:
    try:
        params = {k.lower() for k in parse_qs(urlparse(url).query)}
        return bool(params & _URL_AUTH_PARAMS)
    except Exception:
        return False


def _detect_auth(resp: httpx.Response, url: str = "") -> AuthState:
    www_auth = resp.headers.get("www-authenticate", "").lower()
    if "bearer" in www_auth:
        return AuthState.BEARER
    if "oauth" in www_auth:
        return AuthState.OAUTH
    if _has_url_auth(url):
        return AuthState.API_KEY
    if resp.status_code == 200:
        return AuthState.NONE
    return AuthState.UNKNOWN


def _detect_platform(resp: httpx.Response, url: str) -> Platform:
    h = resp.headers
    if "x-vercel-id" in h or "x-vercel-cache" in h:
        return Platform.VERCEL
    if any(k.startswith("x-railway") for k in h):
        return Platform.RAILWAY
    if "fly-request-id" in h:
        return Platform.FLY
    if "x-amzn-requestid" in h or "x-amzn-trace-id" in h:
        return Platform.AWS_LAMBDA
    if "x-cloud-trace-context" in h or "x-goog-request-id" in h:
        return Platform.GCP
    if "x-ms-request-id" in h or "x-azure-ref" in h:
        return Platform.AZURE
    # URL-based fallback
    for fragment, platform in (
        (".hf.space", Platform.HUGGINGFACE),
        (".vercel.app", Platform.VERCEL),
        (".railway.app", Platform.RAILWAY),
        (".fly.dev", Platform.FLY),
        (".fly.io", Platform.FLY),
        (".onrender.com", Platform.RENDER),
    ):
        if fragment in url:
            return platform
    return Platform.UNKNOWN


async def probe_url(url: str, client: httpx.AsyncClient) -> MCPServerRecord | None:
    """Try to fingerprint a URL as an MCP server. Returns None if not MCP."""
    url = url.rstrip("/")

    result = await _probe_streamable(url, client)
    if result:
        return result

    return await _probe_sse(url, client)


async def probe_urls_batch(
    urls: list[str],
    client: httpx.AsyncClient,
    concurrency: int = 20,
    source_map: dict[str, str] | None = None,
    on_result: Callable[[MCPServerRecord], None] | None = None,
) -> list[MCPServerRecord | None]:
    """Probe a batch of URLs concurrently.

    Args:
        on_result: Optional callback fired for each confirmed MCP server found.
                   Use it for incremental output or progress tracking.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _safe_probe(url: str) -> MCPServerRecord | None:
        async with sem:
            try:
                result = await probe_url(url, client)
                if result is not None and source_map:
                    result.discovered_via = source_map.get(url, "probe")
                if result is not None and on_result:
                    on_result(result)
                return result
            except Exception:
                return None

    return list(await asyncio.gather(*[_safe_probe(u) for u in urls]))


async def _probe_streamable(url: str, client: httpx.AsyncClient) -> MCPServerRecord | None:
    for path in _STREAMABLE_PATHS:
        endpoint = f"{url}{path}"
        resp = None
        for _attempt in range(2):  # PERF-05: max 2 attempts — original + 1 retry on 503 cold start
            try:
                _resp = await client.post(
                    endpoint,
                    json=_INITIALIZE,
                    headers={"Accept": "application/json, text/event-stream"},
                    timeout=httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=5.0),
                )
            except httpx.RequestError:
                break  # resp stays None → skip path
            if _resp.status_code == 503 and _attempt == 0:
                await asyncio.sleep(3)
                continue  # retry once for cold-start 503
            resp = _resp
            break
        if resp is None or resp.status_code == 503:
            continue

        behind_cf = "cf-ray" in resp.headers
        platform = _detect_platform(resp, url)

        if resp.status_code in (401, 403):
            detected = _detect_auth(resp, url)
            return MCPServerRecord(
                url=url,
                protocol=Protocol.STREAMABLE_HTTP,
                auth_state=detected if detected not in (AuthState.NONE, AuthState.UNKNOWN) else AuthState.REQUIRED,
                behind_cloudflare=behind_cf,
                platform=platform,
            )

        if resp.status_code != 200:
            continue

        try:
            data = resp.json()
        except Exception:
            continue

        result = data.get("result", {})

        # FP-001: JSON-RPC error = server is live MCP endpoint (invalid params, not implemented, etc.)
        if "error" in data and "result" not in data:
            return MCPServerRecord(
                url=url,
                protocol=Protocol.STREAMABLE_HTTP,
                auth_state=_detect_auth(resp, url),
                behind_cloudflare=behind_cf,
                platform=platform,
                endpoint_path=path,
            )

        if "protocolVersion" not in result:
            continue

        info = result.get("serverInfo", {})
        auth = _detect_auth(resp, url)

        final_url_str = str(resp.url)
        final_url = final_url_str if final_url_str != endpoint else None

        record = MCPServerRecord(
            url=url,
            protocol=Protocol.STREAMABLE_HTTP,
            server_name=info.get("name"),
            server_version=info.get("version"),
            protocol_version=result.get("protocolVersion"),
            auth_state=auth,
            behind_cloudflare=behind_cf,
            platform=platform,
            endpoint_path=path,
            server_capabilities=result.get("capabilities", {}),
            server_instructions=result.get("instructions"),
            final_url=final_url,
            redirect_count=len(resp.history),
        )
        tools_result, resources, prompts = await asyncio.gather(
            _get_tools(endpoint, client),
            _get_resources(endpoint, client),
            _get_prompts(endpoint, client),
        )
        tools, data_plane_auth = tools_result
        record.tools = tools
        record.resources = resources
        record.prompts = prompts
        # FP-005: tools/list returned 401/403 — data plane is protected even if initialize was open
        if data_plane_auth and record.auth_state == AuthState.NONE:
            record.auth_state = AuthState.REQUIRED
        return record

    return None


async def _probe_sse(url: str, client: httpx.AsyncClient) -> MCPServerRecord | None:
    for path in _SSE_PATHS:
        endpoint = f"{url}{path}"
        try:
            async with client.stream("GET", endpoint, timeout=httpx.Timeout(connect=3.0, read=5.0, write=5.0, pool=5.0)) as resp:
                ct = resp.headers.get("content-type", "")
                if not ct.startswith("text/event-stream"):
                    continue

                behind_cf = "cf-ray" in resp.headers
                platform = _detect_platform(resp, url)
                session_path: str | None = None

                async for raw_line in resp.aiter_lines():
                    line = raw_line.strip()
                    m = _SSE_PATH_RE.match(line)
                    if m:
                        session_path = m.group(1)
                        break
                    if not line:
                        break

                if session_path is None:
                    continue

                auth = _detect_auth(resp, url)
                record = MCPServerRecord(
                    url=url,
                    protocol=Protocol.SSE_LEGACY,
                    auth_state=auth,
                    behind_cloudflare=behind_cf,
                    platform=platform,
                )
                msg_endpoint = url + session_path
                try:
                    init_resp = await client.post(msg_endpoint, json=_INITIALIZE, timeout=httpx.Timeout(connect=3.0, read=5.0, write=5.0, pool=5.0))
                    if init_resp.status_code == 200:
                        data = init_resp.json()
                        result = data.get("result", {})
                        if "serverInfo" in result:
                            info = result["serverInfo"]
                            record.server_name = info.get("name")
                            record.server_version = info.get("version")
                            record.protocol_version = result.get("protocolVersion")
                        tools_result, resources, prompts = await asyncio.gather(
                            _get_tools(msg_endpoint, client),
                            _get_resources(msg_endpoint, client),
                            _get_prompts(msg_endpoint, client),
                        )
                        tools, data_plane_auth = tools_result
                        record.tools = tools
                        record.resources = resources
                        record.prompts = prompts
                        # FP-005: tools/list returned 401/403 — data plane is protected
                        if data_plane_auth and record.auth_state == AuthState.NONE:
                            record.auth_state = AuthState.REQUIRED
                except Exception:
                    pass

                return record

        except (httpx.RequestError, httpx.ReadTimeout):
            continue

    return None


async def _get_tools(endpoint: str, client: httpx.AsyncClient) -> tuple[list[MCPTool], bool]:
    """Returns (tools, data_plane_auth_required).

    data_plane_auth_required is True when tools/list responds 401/403 —
    meaning the server protects its data plane even if initialize was open.
    """
    tools: list[MCPTool] = []
    cursor: str | None = None
    for _ in range(10):  # max 10 pages (1000+ tools is unrealistic)
        req = _TOOLS_LIST_CURSOR(cursor) if cursor else _TOOLS_LIST
        try:
            resp = await client.post(endpoint, json=req, timeout=httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=5.0))
            if resp.status_code in (401, 403):
                return ([], True)
            if resp.status_code != 200:
                break
            data = resp.json()
            result = data.get("result", {})
            for t in result.get("tools", []):
                if t.get("name"):
                    tools.append(MCPTool(
                        name=t["name"],
                        description=t.get("description"),
                        inputSchema=t.get("inputSchema"),
                        annotations=t.get("annotations"),
                    ))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        except Exception:
            break
    return (tools, False)


async def _get_resources(endpoint: str, client: httpx.AsyncClient) -> list[MCPResource]:
    try:
        resp = await client.post(endpoint, json=_RESOURCES_LIST, timeout=httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=5.0))
        if resp.status_code != 200:
            return []
        data = resp.json()
        resources_raw = data.get("result", {}).get("resources", [])
        return [
            MCPResource(
                uri=r.get("uri", ""),
                name=r.get("name"),
                description=r.get("description"),
                mime_type=r.get("mimeType"),
            )
            for r in resources_raw
            if r.get("uri")
        ]
    except Exception:
        return []


async def _get_prompts(endpoint: str, client: httpx.AsyncClient) -> list[MCPPrompt]:
    try:
        resp = await client.post(endpoint, json=_PROMPTS_LIST, timeout=httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=5.0))
        if resp.status_code != 200:
            return []
        data = resp.json()
        prompts_raw = data.get("result", {}).get("prompts", [])
        result = []
        for p in prompts_raw:
            if not p.get("name"):
                continue
            args = [
                MCPPromptArgument(
                    name=a.get("name", ""),
                    description=a.get("description"),
                    required=a.get("required", False),
                )
                for a in p.get("arguments", [])
            ]
            result.append(MCPPrompt(
                name=p["name"],
                description=p.get("description"),
                arguments=args,
            ))
        return result
    except Exception:
        return []
