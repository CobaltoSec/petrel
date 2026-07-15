"""MCP server fingerprinting — SSE legacy and Streamable HTTP."""
from __future__ import annotations

import asyncio

import httpx

from ..models import AuthState, MCPServerRecord, MCPTool, Protocol

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


async def probe_url(url: str, client: httpx.AsyncClient) -> MCPServerRecord | None:
    """Try to fingerprint a URL as an MCP server. Returns None if not MCP."""
    url = url.rstrip("/")

    result = await _probe_streamable(url, client)
    if result:
        return result

    result = await _probe_sse(url, client)
    return result


async def probe_urls_batch(
    urls: list[str], client: httpx.AsyncClient, concurrency: int = 20
) -> list[MCPServerRecord | None]:
    sem = asyncio.Semaphore(concurrency)

    async def _safe_probe(url: str) -> MCPServerRecord | None:
        async with sem:
            try:
                return await probe_url(url, client)
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

        # Cloudflare detection
        behind_cf = "cf-ray" in resp.headers

        if resp.status_code == 401:
            detected = _detect_auth(resp)
            return MCPServerRecord(
                url=url,
                protocol=Protocol.STREAMABLE_HTTP,
                auth_state=detected if detected != AuthState.NONE else AuthState.REQUIRED,
                behind_cloudflare=behind_cf,
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
        auth = _detect_auth(resp)
        record = MCPServerRecord(
            url=url,
            protocol=Protocol.STREAMABLE_HTTP,
            server_name=info.get("name"),
            server_version=info.get("version"),
            protocol_version=result.get("protocolVersion"),
            auth_state=auth,
            behind_cloudflare=behind_cf,
        )
        record.tools = await _get_tools(endpoint, client)
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

                auth = _detect_auth(resp)
                record = MCPServerRecord(
                    url=url,
                    protocol=Protocol.SSE_LEGACY,
                    auth_state=auth,
                    behind_cloudflare=behind_cf,
                )
                # Try to initialize via the messages endpoint
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
                        record.tools = await _get_tools(msg_endpoint, client)
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


def _detect_auth(resp: httpx.Response) -> AuthState:
    www_auth = resp.headers.get("www-authenticate", "").lower()
    if "bearer" in www_auth:
        return AuthState.BEARER
    if "oauth" in www_auth:
        return AuthState.OAUTH

    # If we got a successful response with no auth header, it's open
    if resp.status_code == 200:
        return AuthState.NONE

    return AuthState.UNKNOWN
