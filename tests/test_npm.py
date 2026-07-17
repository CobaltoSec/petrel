"""Tests for npm registry passive discovery."""
from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from petrel.discovery.npm import npm_search

_NPM_URL = re.compile(r"https://registry\.npmjs\.org/-/v1/search")


def _obj(homepage: str) -> dict:
    return {"package": {"links": {"homepage": homepage}}}


@pytest.mark.asyncio
async def test_npm_extracts_homepage_from_links(httpx_mock: HTTPXMock):
    """Package with a deployment homepage URL is included in results."""
    httpx_mock.add_response(
        url=_NPM_URL,
        json={"objects": [_obj("https://my-mcp.vercel.app")]},
        is_reusable=True,
    )
    urls = await npm_search(["mcp-server"])
    assert "https://my-mcp.vercel.app" in urls


@pytest.mark.asyncio
async def test_npm_skips_source_links(httpx_mock: HTTPXMock):
    """github.com / npmjs.com homepages are excluded; real deployments are kept."""
    httpx_mock.add_response(
        url=_NPM_URL,
        json={
            "objects": [
                _obj("https://github.com/user/mcp-server"),
                _obj("https://npmjs.com/package/mcp-server"),
                _obj("https://live-mcp.onrender.com"),
            ]
        },
        is_reusable=True,
    )
    urls = await npm_search(["mcp-server"])
    assert "https://github.com/user/mcp-server" not in urls
    assert "https://npmjs.com/package/mcp-server" not in urls
    assert "https://live-mcp.onrender.com" in urls


@pytest.mark.asyncio
async def test_npm_deduplicates_across_queries(httpx_mock: HTTPXMock):
    """Same URL returned by multiple concurrent queries appears only once."""
    httpx_mock.add_response(
        url=_NPM_URL,
        json={"objects": [_obj("https://shared.hf.space")]},
        is_reusable=True,
    )
    urls = await npm_search(["q1", "q2"])
    assert urls.count("https://shared.hf.space") == 1


@pytest.mark.asyncio
async def test_npm_empty_objects_returns_empty(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_NPM_URL, json={"objects": []}, is_reusable=True)
    urls = await npm_search(["mcp-server"])
    assert urls == []


@pytest.mark.asyncio
async def test_npm_api_error_returns_empty(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_NPM_URL, status_code=500, is_reusable=True)
    urls = await npm_search(["mcp-server"])
    assert urls == []
