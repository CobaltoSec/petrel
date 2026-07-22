"""Tests for MCP fingerprint probe."""
from __future__ import annotations

import pytest
import httpx
from pytest_httpx import HTTPXMock

from petrel.fingerprint.probe import probe_url, probe_urls_batch, _has_url_auth, _detect_auth
from petrel.models import AuthState, MCPResource, MCPPrompt, Platform, Protocol


@pytest.mark.asyncio
async def test_probe_streamable_http_confirmed(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://target.example.com/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "test-server", "version": "1.0.0"},
                "capabilities": {},
            },
        },
    )
    # tools/list call
    httpx_mock.add_response(
        method="POST",
        url="http://target.example.com/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {"name": "execute_bash", "description": "Run bash commands"},
                    {"name": "read_file", "description": "Read a file"},
                ],
            },
        },
    )
    # resources/list call (F2)
    httpx_mock.add_response(
        method="POST",
        url="http://target.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 3, "result": {"resources": []}},
    )
    # prompts/list call (F2)
    httpx_mock.add_response(
        method="POST",
        url="http://target.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 4, "result": {"prompts": []}},
    )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://target.example.com", client)

    assert record is not None
    assert record.protocol == Protocol.STREAMABLE_HTTP
    assert record.server_name == "test-server"
    assert record.auth_state == AuthState.NONE
    assert len(record.tools) == 2
    assert record.tools[0].name == "execute_bash"


@pytest.mark.asyncio
async def test_probe_returns_none_for_non_mcp(httpx_mock: HTTPXMock):
    # All paths return non-MCP responses
    for path in ["/mcp", "/", "/api/mcp", "/api", "/v1/mcp"]:
        httpx_mock.add_response(
            method="POST",
            url=f"http://notmcp.example.com{path}",
            status_code=404,
        )
    for path in ["/sse", "/api/sse", "/mcp/sse", "/events"]:
        httpx_mock.add_response(
            method="GET",
            url=f"http://notmcp.example.com{path}",
            status_code=404,
        )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://notmcp.example.com", client)

    assert record is None


@pytest.mark.asyncio
async def test_probe_detects_auth_required(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://protected.example.com/mcp",
        status_code=401,
        headers={"www-authenticate": "Bearer realm=api"},
    )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://protected.example.com", client)

    assert record is not None
    assert record.protocol == Protocol.STREAMABLE_HTTP
    assert record.auth_state == AuthState.BEARER


# ---------------------------------------------------------------------------
# F1 — endpoint_path, server_capabilities, server_instructions
# ---------------------------------------------------------------------------

def _make_init_response(extra_result: dict | None = None) -> dict:
    base = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "f1-server", "version": "2.0.0"},
            "capabilities": {"tools": {}, "resources": {}},
        },
    }
    if extra_result:
        base["result"].update(extra_result)
    return base


def _add_primitives_mocks(httpx_mock: HTTPXMock, url: str) -> None:
    """Add empty tools/resources/prompts mock responses for a given URL."""
    httpx_mock.add_response(
        method="POST", url=url,
        json={"jsonrpc": "2.0", "id": 2, "result": {"tools": []}},
    )
    httpx_mock.add_response(
        method="POST", url=url,
        json={"jsonrpc": "2.0", "id": 3, "result": {"resources": []}},
    )
    httpx_mock.add_response(
        method="POST", url=url,
        json={"jsonrpc": "2.0", "id": 4, "result": {"prompts": []}},
    )


@pytest.mark.asyncio
async def test_f1_endpoint_path_stored(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://f1.example.com/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://f1.example.com/mcp")

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://f1.example.com", client)

    assert record is not None
    assert record.endpoint_path == "/mcp"


@pytest.mark.asyncio
async def test_f1_server_capabilities_stored(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://f1caps.example.com/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://f1caps.example.com/mcp")

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://f1caps.example.com", client)

    assert record is not None
    assert record.server_capabilities == {"tools": {}, "resources": {}}


@pytest.mark.asyncio
async def test_f1_server_instructions_stored(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://f1inst.example.com/mcp",
        json=_make_init_response({"instructions": "You are a helpful MCP server."}),
    )
    _add_primitives_mocks(httpx_mock, "http://f1inst.example.com/mcp")

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://f1inst.example.com", client)

    assert record is not None
    assert record.server_instructions == "You are a helpful MCP server."


# ---------------------------------------------------------------------------
# F2 — resources/list and prompts/list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_f2_resources_returned(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://f2res.example.com/mcp",
        json=_make_init_response(),
    )
    # tools/list — empty
    httpx_mock.add_response(
        method="POST",
        url="http://f2res.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {"tools": []}},
    )
    # resources/list — two resources
    httpx_mock.add_response(
        method="POST",
        url="http://f2res.example.com/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "resources": [
                    {"uri": "file:///data/readme.md", "name": "Readme", "mimeType": "text/markdown"},
                    {"uri": "file:///data/config.json", "name": "Config"},
                ],
            },
        },
    )
    # prompts/list — empty
    httpx_mock.add_response(
        method="POST",
        url="http://f2res.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 4, "result": {"prompts": []}},
    )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://f2res.example.com", client)

    assert record is not None
    assert len(record.resources) == 2
    assert isinstance(record.resources[0], MCPResource)
    assert record.resources[0].uri == "file:///data/readme.md"
    assert record.resources[0].name == "Readme"
    assert record.resources[0].mime_type == "text/markdown"
    assert record.resources[1].uri == "file:///data/config.json"


@pytest.mark.asyncio
async def test_f2_prompts_returned(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://f2prom.example.com/mcp",
        json=_make_init_response(),
    )
    # tools/list — empty
    httpx_mock.add_response(
        method="POST",
        url="http://f2prom.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {"tools": []}},
    )
    # resources/list — empty
    httpx_mock.add_response(
        method="POST",
        url="http://f2prom.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 3, "result": {"resources": []}},
    )
    # prompts/list — one prompt with arguments
    httpx_mock.add_response(
        method="POST",
        url="http://f2prom.example.com/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "result": {
                "prompts": [
                    {
                        "name": "summarize",
                        "description": "Summarize a document",
                        "arguments": [
                            {"name": "text", "description": "Text to summarize", "required": True},
                            {"name": "length", "required": False},
                        ],
                    }
                ],
            },
        },
    )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://f2prom.example.com", client)

    assert record is not None
    assert len(record.prompts) == 1
    assert isinstance(record.prompts[0], MCPPrompt)
    assert record.prompts[0].name == "summarize"
    assert record.prompts[0].description == "Summarize a document"
    assert len(record.prompts[0].arguments) == 2
    assert record.prompts[0].arguments[0].name == "text"
    assert record.prompts[0].arguments[0].required is True
    assert record.prompts[0].arguments[1].required is False


# ---------------------------------------------------------------------------
# F3 — platform detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_f3_platform_vercel_from_header(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://myapp.example.com/mcp",
        json=_make_init_response(),
        headers={"x-vercel-id": "iad1::abc123"},
    )
    _add_primitives_mocks(httpx_mock, "http://myapp.example.com/mcp")

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://myapp.example.com", client)

    assert record is not None
    assert record.platform == Platform.VERCEL


@pytest.mark.asyncio
async def test_f3_platform_huggingface_from_url(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://user-mymodel.hf.space/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://user-mymodel.hf.space/mcp")

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://user-mymodel.hf.space", client)

    assert record is not None
    assert record.platform == Platform.HUGGINGFACE


# ---------------------------------------------------------------------------
# F4 — API key in URL detection
# ---------------------------------------------------------------------------

def test_f4_has_url_auth_detects_api_key():
    assert _has_url_auth("https://server.example.com/mcp?api_key=secret123") is True


def test_f4_has_url_auth_detects_token():
    assert _has_url_auth("https://server.example.com?token=abc") is True


def test_f4_has_url_auth_no_match():
    assert _has_url_auth("https://server.example.com/mcp?foo=bar&baz=qux") is False


def test_f4_detect_auth_api_key_in_url():
    resp = httpx.Response(200)
    auth = _detect_auth(resp, "https://server.example.com/mcp?api_key=secret")
    assert auth == AuthState.API_KEY


def test_f4_detect_auth_bearer_takes_priority_over_url():
    """WWW-Authenticate: Bearer should win over URL api_key."""
    resp = httpx.Response(401, headers={"www-authenticate": "Bearer realm=api"})
    auth = _detect_auth(resp, "https://server.example.com/mcp?api_key=secret")
    assert auth == AuthState.BEARER


# ---------------------------------------------------------------------------
# F5 — source_map in probe_urls_batch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_f5_probe_batch_source_map(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://batchsrv.example.com/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://batchsrv.example.com/mcp")

    source_map = {"http://batchsrv.example.com": "github"}

    async with httpx.AsyncClient() as client:
        results = await probe_urls_batch(
            ["http://batchsrv.example.com"],
            client,
            source_map=source_map,
        )

    assert len(results) == 1
    record = results[0]
    assert record is not None
    assert record.discovered_via == "github"


@pytest.mark.asyncio
async def test_f5_probe_batch_source_map_fallback(httpx_mock: HTTPXMock):
    """URL not in source_map falls back to 'probe'."""
    httpx_mock.add_response(
        method="POST",
        url="http://batchfb.example.com/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://batchfb.example.com/mcp")

    source_map: dict[str, str] = {}  # empty — no mapping for this URL

    async with httpx.AsyncClient() as client:
        results = await probe_urls_batch(
            ["http://batchfb.example.com"],
            client,
            source_map=source_map,
        )

    assert len(results) == 1
    record = results[0]
    assert record is not None
    assert record.discovered_via == "probe"


# ---------------------------------------------------------------------------
# PERF-07 — progress callback invoked for each confirmed server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_perf07_on_result_callback_invoked(httpx_mock: HTTPXMock):
    """on_result callback is fired once per confirmed MCP server in probe_urls_batch."""
    httpx_mock.add_response(
        method="POST",
        url="http://perf07a.example.com/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://perf07a.example.com/mcp")
    # Second URL: not an MCP server (404 on all paths)
    for path in ["/mcp", "/", "/api/mcp", "/api", "/v1/mcp"]:
        httpx_mock.add_response(
            method="POST",
            url=f"http://perf07b.example.com{path}",
            status_code=404,
        )
    for path in ["/sse", "/api/sse", "/mcp/sse", "/events"]:
        httpx_mock.add_response(
            method="GET",
            url=f"http://perf07b.example.com{path}",
            status_code=404,
        )

    called_with: list = []

    async with httpx.AsyncClient() as client:
        await probe_urls_batch(
            ["http://perf07a.example.com", "http://perf07b.example.com"],
            client,
            on_result=called_with.append,
        )

    # Callback fired once for the confirmed server, not for the non-MCP one
    assert len(called_with) == 1
    assert called_with[0].url == "http://perf07a.example.com"


# ---------------------------------------------------------------------------
# FP-002, FP-003, FP-001 — fingerprint false-positive fixes
# ---------------------------------------------------------------------------

from unittest.mock import AsyncMock, MagicMock


def _make_resp(status, body=None, headers=None):
    """Helper: mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.json = lambda: body or {}
    resp.url = "https://example.com/mcp"
    resp.history = []
    return resp


@pytest.mark.asyncio
async def test_fp002_protocolversion_without_serverinfo():
    """Server con protocolVersion pero sin serverInfo debe ser confirmado."""
    from petrel.fingerprint.probe import _probe_streamable

    body = {"result": {"protocolVersion": "2024-11-05", "capabilities": {}}}
    resp = _make_resp(200, body)

    client = AsyncMock()
    client.post = AsyncMock(return_value=resp)

    record = await _probe_streamable("https://example.com", client)
    assert record is not None
    assert record.protocol.value == "streamable-http"
    assert record.server_name is None  # serverInfo ausente → None


@pytest.mark.asyncio
async def test_fp003_403_returns_auth_required():
    """403 Forbidden debe crear record con AuthState.REQUIRED."""
    from petrel.fingerprint.probe import _probe_streamable

    resp = _make_resp(403, headers={})
    client = AsyncMock()
    client.post = AsyncMock(return_value=resp)

    record = await _probe_streamable("https://example.com", client)
    assert record is not None
    assert record.auth_state.value == "required"


@pytest.mark.asyncio
async def test_fp001_jsonrpc_error_returns_partial_record():
    """JSON-RPC error response = endpoint MCP confirmado."""
    from petrel.fingerprint.probe import _probe_streamable

    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}}
    resp = _make_resp(200, body)
    client = AsyncMock()
    client.post = AsyncMock(return_value=resp)

    record = await _probe_streamable("https://example.com", client)
    assert record is not None
    assert record.is_confirmed_mcp is True
    assert record.protocol.value == "streamable-http"


# ---------------------------------------------------------------------------
# FP-007 — SSE session path regex
# ---------------------------------------------------------------------------

from petrel.fingerprint.probe import _probe_sse


def _add_sse_post_mocks(httpx_mock: HTTPXMock, msg_url: str) -> None:
    """Add init + tools/resources/prompts mocks for an SSE message endpoint."""
    httpx_mock.add_response(
        method="POST",
        url=msg_url,
        json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {}}},
    )
    httpx_mock.add_response(method="POST", url=msg_url, json={"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    httpx_mock.add_response(method="POST", url=msg_url, json={"jsonrpc": "2.0", "id": 3, "result": {"resources": []}})
    httpx_mock.add_response(method="POST", url=msg_url, json={"jsonrpc": "2.0", "id": 4, "result": {"prompts": []}})


@pytest.mark.asyncio
async def test_fp007_sse_path_messages_querystring(httpx_mock: HTTPXMock):
    """SSE sends data: /messages?sessionId=abc → session_path extracted correctly."""
    httpx_mock.add_response(
        method="GET",
        url="http://sse7a.example.com/sse",
        headers={"content-type": "text/event-stream"},
        content=b"data: /messages?sessionId=abc\n\n",
    )
    _add_sse_post_mocks(httpx_mock, "http://sse7a.example.com/messages?sessionId=abc")

    async with httpx.AsyncClient() as client:
        record = await _probe_sse("http://sse7a.example.com", client)

    assert record is not None
    assert record.protocol == Protocol.SSE_LEGACY


@pytest.mark.asyncio
async def test_fp007_sse_path_api_v1_session(httpx_mock: HTTPXMock):
    """SSE sends data: /api/v1/session/123/messages → extracted correctly."""
    httpx_mock.add_response(
        method="GET",
        url="http://sse7b.example.com/sse",
        headers={"content-type": "text/event-stream"},
        content=b"data: /api/v1/session/123/messages\n\n",
    )
    _add_sse_post_mocks(httpx_mock, "http://sse7b.example.com/api/v1/session/123/messages")

    async with httpx.AsyncClient() as client:
        record = await _probe_sse("http://sse7b.example.com", client)

    assert record is not None
    assert record.protocol == Protocol.SSE_LEGACY


@pytest.mark.asyncio
async def test_fp007_sse_path_connect_no_messages(httpx_mock: HTTPXMock):
    """SSE sends data: /connect (no /messages) → still extracted (regression: old code would miss this)."""
    httpx_mock.add_response(
        method="GET",
        url="http://sse7c.example.com/sse",
        headers={"content-type": "text/event-stream"},
        content=b"data: /connect\n\n",
    )
    _add_sse_post_mocks(httpx_mock, "http://sse7c.example.com/connect")

    async with httpx.AsyncClient() as client:
        record = await _probe_sse("http://sse7c.example.com", client)

    assert record is not None
    assert record.protocol == Protocol.SSE_LEGACY


# ---------------------------------------------------------------------------
# FP-008 — Tool annotations
# ---------------------------------------------------------------------------

from petrel.fingerprint.probe import _get_tools


@pytest.mark.asyncio
async def test_fp008_tool_annotations_populated(httpx_mock: HTTPXMock):
    """Tool with annotations → MCPTool.annotations populated."""
    httpx_mock.add_response(
        method="POST",
        url="http://ann8a.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [
                {"name": "read_file", "description": "Read a file", "annotations": {"readOnly": True, "safe": True}},
            ],
        }},
    )

    async with httpx.AsyncClient() as client:
        tools, _ = await _get_tools("http://ann8a.example.com/mcp", client)

    assert len(tools) == 1
    assert tools[0].annotations == {"readOnly": True, "safe": True}


@pytest.mark.asyncio
async def test_fp008_tool_no_annotations_is_none(httpx_mock: HTTPXMock):
    """Tool without annotations → MCPTool.annotations is None."""
    httpx_mock.add_response(
        method="POST",
        url="http://ann8b.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "execute", "description": "Execute"}],
        }},
    )

    async with httpx.AsyncClient() as client:
        tools, _ = await _get_tools("http://ann8b.example.com/mcp", client)

    assert len(tools) == 1
    assert tools[0].annotations is None


# ---------------------------------------------------------------------------
# FP-009 — tools/list cursor pagination
# ---------------------------------------------------------------------------

import re as _re


@pytest.mark.asyncio
async def test_fp009_cursor_pagination_two_pages(httpx_mock: HTTPXMock):
    """Server returns 3 tools + nextCursor on page 1, 2 tools on page 2 → total 5."""
    httpx_mock.add_response(
        method="POST",
        url="http://cur9a.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "t1"}, {"name": "t2"}, {"name": "t3"}],
            "nextCursor": "cursor_pg2",
        }},
    )
    httpx_mock.add_response(
        method="POST",
        url="http://cur9a.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "t4"}, {"name": "t5"}],
        }},
    )

    async with httpx.AsyncClient() as client:
        tools, _ = await _get_tools("http://cur9a.example.com/mcp", client)

    assert len(tools) == 5
    assert [t.name for t in tools] == ["t1", "t2", "t3", "t4", "t5"]


@pytest.mark.asyncio
async def test_fp009_no_cursor_single_request(httpx_mock: HTTPXMock):
    """Server with no nextCursor → single request (existing behavior preserved)."""
    httpx_mock.add_response(
        method="POST",
        url="http://cur9b.example.com/mcp",
        json={"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "tool1"}, {"name": "tool2"}],
        }},
    )

    async with httpx.AsyncClient() as client:
        tools, _ = await _get_tools("http://cur9b.example.com/mcp", client)

    assert len(tools) == 2


@pytest.mark.asyncio
async def test_fp009_cursor_max_10_pages(httpx_mock: HTTPXMock):
    """Cursor loop stops at max 10 pages even when server always returns nextCursor."""
    httpx_mock.add_response(
        method="POST",
        url=_re.compile(r"http://cur9c\.example\.com/mcp"),
        is_reusable=True,
        json={"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "tool"}],
            "nextCursor": "always_more",
        }},
    )

    async with httpx.AsyncClient() as client:
        tools, _ = await _get_tools("http://cur9c.example.com/mcp", client)

    # 10 pages × 1 tool = 10 tools
    assert len(tools) == 10


# ---------------------------------------------------------------------------
# FP-011 — response_time_ms tracking
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fp011_response_time_ms_set(httpx_mock: HTTPXMock):
    """Confirmed MCP server has response_time_ms set to a non-negative int."""
    httpx_mock.add_response(
        method="POST",
        url="http://timing.example.com/mcp",
        json=_make_init_response(),
    )
    _add_primitives_mocks(httpx_mock, "http://timing.example.com/mcp")

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://timing.example.com", client)

    assert record is not None
    assert record.response_time_ms is not None
    assert isinstance(record.response_time_ms, int)
    assert record.response_time_ms >= 0


# ---------------------------------------------------------------------------
# FP-012 — Probe failure classification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fp012_probe_error_down(httpx_mock: HTTPXMock):
    """ConnectError → probe_error_type='down', not confirmed MCP."""
    httpx_mock.add_exception(
        httpx.ConnectError("Connection refused"),
        method="POST",
        url="http://down.example.com/mcp",
    )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://down.example.com", client)

    assert record is not None
    assert record.probe_error_type == "down"
    assert not record.is_confirmed_mcp


@pytest.mark.asyncio
async def test_fp012_probe_error_timeout(httpx_mock: HTTPXMock):
    """ReadTimeout → probe_error_type='timeout', not confirmed MCP."""
    httpx_mock.add_exception(
        httpx.ReadTimeout("Read timed out"),
        method="POST",
        url="http://slow.example.com/mcp",
    )

    async with httpx.AsyncClient() as client:
        record = await probe_url("http://slow.example.com", client)

    assert record is not None
    assert record.probe_error_type == "timeout"
    assert not record.is_confirmed_mcp


@pytest.mark.asyncio
async def test_fp012_probe_batch_returns_failure_records(httpx_mock: HTTPXMock):
    """probe_urls_batch returns MCPServerRecord (not None) for failures."""
    httpx_mock.add_exception(
        httpx.ConnectError("refused"),
        method="POST",
        url="http://batchdown.example.com/mcp",
    )

    async with httpx.AsyncClient() as client:
        results = await probe_urls_batch(["http://batchdown.example.com"], client)

    assert len(results) == 1
    assert results[0].probe_error_type == "down"
    assert not results[0].is_confirmed_mcp


# ---------------------------------------------------------------------------
# FP-004 — Basic auth and X-Api-Key-Required header detection
# ---------------------------------------------------------------------------

def test_fp004_detect_auth_basic():
    """WWW-Authenticate: Basic → AuthState.REQUIRED."""
    resp = httpx.Response(401, headers={"www-authenticate": 'Basic realm="restricted"'})
    auth = _detect_auth(resp)
    assert auth == AuthState.REQUIRED


def test_fp004_detect_auth_api_key_required_header():
    """X-Api-Key-Required: true → AuthState.API_KEY."""
    resp = httpx.Response(200, headers={"x-api-key-required": "true"})
    auth = _detect_auth(resp)
    assert auth == AuthState.API_KEY


def test_fp004_detect_auth_api_key_required_1():
    """X-Api-Key-Required: 1 → AuthState.API_KEY."""
    resp = httpx.Response(200, headers={"x-api-key-required": "1"})
    auth = _detect_auth(resp)
    assert auth == AuthState.API_KEY


# ---------------------------------------------------------------------------
# FP-006 — Per-domain throttling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fp006_domain_semaphore_created_for_railway(httpx_mock: HTTPXMock):
    """railway.app URLs cause a domain semaphore to be created in _domain_sems."""
    from petrel.fingerprint.probe import _domain_sems

    httpx_mock.add_exception(
        httpx.ConnectError("refused"),
        method="POST",
        url="http://myapp.railway.app/mcp",
    )

    async with httpx.AsyncClient() as client:
        await probe_urls_batch(["http://myapp.railway.app"], client)

    assert ".railway.app" in _domain_sems


@pytest.mark.asyncio
async def test_fp006_non_throttled_domain_no_semaphore(httpx_mock: HTTPXMock):
    """Non-throttled domains do not create entries in _domain_sems."""
    from petrel.fingerprint.probe import _domain_sems

    for path in ["/mcp", "/", "/api/mcp", "/api", "/v1/mcp"]:
        httpx_mock.add_response(
            method="POST",
            url=f"http://myapp.example.com{path}",
            status_code=404,
        )
    for path in ["/sse", "/api/sse", "/mcp/sse", "/events"]:
        httpx_mock.add_response(
            method="GET",
            url=f"http://myapp.example.com{path}",
            status_code=404,
        )

    async with httpx.AsyncClient() as client:
        await probe_urls_batch(["http://myapp.example.com"], client)

    # No throttle semaphore created for plain .example.com
    assert "example.com" not in _domain_sems
