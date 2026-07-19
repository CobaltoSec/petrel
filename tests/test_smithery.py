"""Tests for Smithery.ai discovery."""
from __future__ import annotations
import re
import pytest
from pytest_httpx import HTTPXMock
from petrel.discovery.smithery import smithery_search

_URL = re.compile(r"https://smithery\.ai/api/v1/servers")


@pytest.mark.asyncio
async def test_smithery_returns_deployment_urls(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_URL,
        json={"servers": [{"homepage": "https://my-mcp.railway.app"}], "total": 1},
    )
    urls = await smithery_search()
    assert "https://my-mcp.railway.app" in urls


@pytest.mark.asyncio
async def test_smithery_pagination(httpx_mock: HTTPXMock):
    # page 1: full page (100 items)
    servers_p1 = [{"homepage": f"https://server-{i}.hf.space"} for i in range(100)]
    httpx_mock.add_response(url=_URL, json={"servers": servers_p1, "total": 105})
    # page 2: partial (5 items)
    servers_p2 = [{"homepage": f"https://server-extra-{i}.hf.space"} for i in range(5)]
    httpx_mock.add_response(url=_URL, json={"servers": servers_p2, "total": 105})
    urls = await smithery_search()
    assert len(urls) == 105


@pytest.mark.asyncio
async def test_smithery_prefers_homepage_over_deploymentUrl(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_URL,
        json={"servers": [{"homepage": "https://home.vercel.app", "deploymentUrl": "https://deploy.vercel.app"}], "total": 1},
    )
    urls = await smithery_search()
    assert "https://home.vercel.app" in urls
    assert "https://deploy.vercel.app" not in urls


@pytest.mark.asyncio
async def test_smithery_skips_source_links(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_URL,
        json={"servers": [{"homepage": "https://github.com/user/mcp-server"}], "total": 1},
    )
    urls = await smithery_search()
    assert urls == []


@pytest.mark.asyncio
async def test_smithery_api_error_returns_empty(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_URL, status_code=500)
    urls = await smithery_search()
    assert urls == []


@pytest.mark.asyncio
async def test_smithery_empty_servers_stops_pagination(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_URL, json={"servers": [], "total": 0})
    urls = await smithery_search()
    assert urls == []


# ---------------------------------------------------------------------------
# DISC-001: API key support
# ---------------------------------------------------------------------------

def _make_smithery_resp(status, data=None):
    from unittest.mock import MagicMock
    resp = MagicMock()
    resp.status_code = status
    resp.json = lambda: data or {}
    return resp


@pytest.mark.asyncio
async def test_smithery_401_returns_empty_and_warns(capsys):
    from unittest.mock import AsyncMock, patch, MagicMock
    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=_make_smithery_resp(401))
        mock_client_cls.return_value = mock_client
        result = await smithery_search(api_key=None)
    assert result == []
    captured = capsys.readouterr()
    assert "SMITHERY_API_KEY" in captured.err


@pytest.mark.asyncio
async def test_smithery_with_key_sends_bearer_header():
    from unittest.mock import AsyncMock, patch

    async def fake_get(url, **kwargs):
        return _make_smithery_resp(200, {"servers": [], "total": 0})

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = fake_get
        mock_client_cls.return_value = mock_client
        await smithery_search(api_key="test-key-123")
    # Authorization header was passed to AsyncClient constructor
    init_kwargs = mock_client_cls.call_args[1]
    assert init_kwargs.get("headers", {}).get("Authorization") == "Bearer test-key-123"
