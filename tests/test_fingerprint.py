"""Tests for MCP fingerprint probe."""
from __future__ import annotations

import pytest
import httpx
from pytest_httpx import HTTPXMock

from petrel.fingerprint.probe import probe_url
from petrel.models import AuthState, Protocol


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
