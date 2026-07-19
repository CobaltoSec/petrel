"""MCP server fingerprinting — SSE legacy and Streamable HTTP."""
from __future__ import annotations

import asyncio
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
_RESOURCES_LIST = {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}
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
) -> list[MCPServerRecord | None]:
    sem = asyncio.Semaphore(concurrency)

    async def _safe_probe(url: str) -> MCPServerRecord | None:
        async with sem:
            try:
                result = await probe_url(url, client)
                if result is not None and source_map:
                    result.discovered_via = source_map.get(url, "probe")
                return result
            except Exception:
                return None

    return list(await asyncio.gather(*[_safe_probe(u) for u in urls]))


async def _probe_streamable(url: str, client: httpx.AsyncClient) -> MCPServerRecord | None:
    for path in _STREAMABLE_PATHS:
        endpoint = f"{url}{path}"
        try:
            resp = await client.post(
                endpoint,
                json=_INITIALIZE,
                headers={"Accept": "application/json, text/event-stream"},
                timeout=8.0,
            )
        except httpx.RequestError:
            continue

        behind_cf = "cf-ray" in resp.headers
        platform = _detect_platform(resp, url)

        if resp.status_code == 401:
            detected = _detect_auth(resp, url)
            return MCPServerRecord(
                url=url,
                protocol=Protocol.STREAMABLE_HTTP,
                auth_state=detected if detected != AuthState.NONE else AuthState.REQUIRED,
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
        if "serverInfo" not in result:
            continue

        info = result["serverInfo"]
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
        record.tools, record.resources, record.prompts = await asyncio.gather(
            _get_tools(endpoint, client),
            _get_resources(endpoint, client),
            _get_prompts(endpoint, client),
        )
        return record

    return None


async def _probe_sse(url: str, client: httpx.AsyncClient) -> MCPServerRecord | None:
    for path in _SSE_PATHS:
        endpoint = f"{url}{path}"
        try:
            async with client.stream("GET", endpoint, timeout=5.0) as resp:
                ct = resp.headers.get("content-type", "")
                if not ct.startswith("text/event-stream"):
                    continue

                behind_cf = "cf-ray" in resp.headers
                platform = _detect_platform(resp, url)
                session_path: str | None = None

                async for raw_line in resp.aiter_lines():
                    line = raw_line.strip()
                    if line.startswith("data:") and "/messages" in line:
                        session_path = line[5:].strip()
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
                    init_resp = await client.post(msg_endpoint, json=_INITIALIZE, timeout=5.0)
                    if init_resp.status_code == 200:
                        data = init_resp.json()
                        result = data.get("result", {})
                        if "serverInfo" in result:
                            info = result["serverInfo"]
                            record.server_name = info.get("name")
                            record.server_version = info.get("version")
                            record.protocol_version = result.get("protocolVersion")
                        record.tools, record.resources, record.prompts = await asyncio.gather(
                            _get_tools(msg_endpoint, client),
                            _get_resources(msg_endpoint, client),
                            _get_prompts(msg_endpoint, client),
                        )
                except Exception:
                    pass

                return record

        except (httpx.RequestError, httpx.ReadTimeout):
            continue

    return None


async def _get_tools(endpoint: str, client: httpx.AsyncClient) -> list[MCPTool]:
    try:
        resp = await client.post(endpoint, json=_TOOLS_LIST, timeout=8.0)
        if resp.status_code != 200:
            return []
        data = resp.json()
        tools_raw = data.get("result", {}).get("tools", [])
        return [
            MCPTool(
                name=t.get("name", ""),
                description=t.get("description"),
                inputSchema=t.get("inputSchema"),
            )
            for t in tools_raw
            if t.get("name")
        ]
    except Exception:
        return []


async def _get_resources(endpoint: str, client: httpx.AsyncClient) -> list[MCPResource]:
    try:
        resp = await client.post(endpoint, json=_RESOURCES_LIST, timeout=8.0)
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
        resp = await client.post(endpoint, json=_PROMPTS_LIST, timeout=8.0)
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
