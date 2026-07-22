"""Tests for Smithery.ai discovery — new API (api.smithery.ai)."""
from __future__ import annotations
import re
import pytest
from pytest_httpx import HTTPXMock
from petrel.discovery.smithery import smithery_search

_LIST_URL = re.compile(r"https://api\.smithery\.ai/servers(\?.*)?$")


def _list_resp(servers: list, total_pages: int = 1, page: int = 1) -> dict:
    return {
        "servers": servers,
        "pagination": {
            "currentPage": page,
            "pageSize": 100,
            "totalPages": total_pages,
            "totalCount": len(servers),
        },
    }


def _server(homepage: str, by_smithery: bool = False) -> dict:
    return {"qualifiedName": "test", "bySmithery": by_smithery, "homepage": homepage, "isDeployed": True}


# ---------------------------------------------------------------------------
# Basic happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smithery_returns_homepage_urls(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([_server("https://my-mcp.railway.app")]))
    result = await smithery_search(api_key="test-key")
    assert "https://my-mcp.railway.app" in result.urls


@pytest.mark.asyncio
async def test_smithery_deduplicates_urls(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([
        _server("https://same.railway.app"),
        _server("https://same.railway.app"),
    ]))
    result = await smithery_search(api_key="test-key")
    assert result.urls.count("https://same.railway.app") == 1


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smithery_skips_run_tools_urls(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([_server("https://myserver.run.tools")]))
    result = await smithery_search(api_key="test-key")
    assert result.urls == []


@pytest.mark.asyncio
async def test_smithery_skips_smithery_ai_urls(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([_server("https://smithery.ai/servers/myserver")]))
    result = await smithery_search(api_key="test-key")
    assert result.urls == []


@pytest.mark.asyncio
async def test_smithery_skips_github_urls(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([_server("https://github.com/user/repo")]))
    result = await smithery_search(api_key="test-key")
    assert result.urls == []


@pytest.mark.asyncio
async def test_smithery_skips_empty_homepage(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([_server("")]))
    result = await smithery_search(api_key="test-key")
    assert result.urls == []


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smithery_pagination(httpx_mock: HTTPXMock):
    page1 = [_server(f"https://server-{i}.vercel.app") for i in range(3)]
    page2 = [_server(f"https://server-extra-{i}.fly.dev") for i in range(2)]
    httpx_mock.add_response(url=_LIST_URL, json={
        "servers": page1,
        "pagination": {"currentPage": 1, "pageSize": 3, "totalPages": 2, "totalCount": 5},
    })
    httpx_mock.add_response(url=_LIST_URL, json={
        "servers": page2,
        "pagination": {"currentPage": 2, "pageSize": 3, "totalPages": 2, "totalCount": 5},
    })
    result = await smithery_search(api_key="test-key")
    assert len(result.urls) == 5
    assert len(httpx_mock.get_requests()) == 2  # exactly 2 pages fetched


# ---------------------------------------------------------------------------
# Auth / error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smithery_no_key_warns_and_returns_empty(monkeypatch, capsys):
    monkeypatch.delenv("SMITHERY_API_KEY", raising=False)
    result = await smithery_search(api_key=None)
    assert result.urls == []
    assert "SMITHERY_API_KEY" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_smithery_401_returns_empty_and_warns(httpx_mock: HTTPXMock, capsys):
    httpx_mock.add_response(url=_LIST_URL, status_code=401)
    result = await smithery_search(api_key="bad-key")
    assert result.urls == []
    assert "SMITHERY_API_KEY" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_smithery_500_returns_empty(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, status_code=500)
    result = await smithery_search(api_key="test-key")
    assert result.urls == []


@pytest.mark.asyncio
async def test_smithery_empty_servers_stops(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([]))
    result = await smithery_search(api_key="test-key")
    assert result.urls == []


# ---------------------------------------------------------------------------
# Bearer header sent
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smithery_with_key_sends_bearer_header(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_LIST_URL, json=_list_resp([]))
    await smithery_search(api_key="test-key-123")
    req = httpx_mock.get_requests()[0]
    assert req.headers.get("authorization") == "Bearer test-key-123"
