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
