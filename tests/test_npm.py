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


# ---------------------------------------------------------------------------
# Pagination tests (DISC-009)
# ---------------------------------------------------------------------------

def _full_page(start: int = 0) -> list[dict]:
    """Return exactly 250 package objects with distinct deployment URLs."""
    return [_obj(f"https://pkg{start + i}.example.com") for i in range(250)]


@pytest.mark.asyncio
async def test_npm_single_page_no_second_request(httpx_mock: HTTPXMock):
    """Fewer than 250 results on page 1 → only one HTTP request is made."""
    httpx_mock.add_response(
        url=_NPM_URL,
        json={"objects": [_obj("https://only.example.com")]},
        # not reusable: consumed once; a second request would raise
    )
    urls = await npm_search(["mcp-server"])
    assert "https://only.example.com" in urls


@pytest.mark.asyncio
async def test_npm_two_pages(httpx_mock: HTTPXMock):
    """Full first page (250) triggers a second request; partial second page stops."""
    page1 = _full_page(start=0)    # 250 objects → from=0
    page2 = [_obj(f"https://pkg{250 + i}.example.com") for i in range(50)]  # 50 → stop
    httpx_mock.add_response(url=_NPM_URL, json={"objects": page1})
    httpx_mock.add_response(url=_NPM_URL, json={"objects": page2})
    urls = await npm_search(["mcp-server"])
    assert len(urls) == 300
    assert "https://pkg0.example.com" in urls
    assert "https://pkg299.example.com" in urls


@pytest.mark.asyncio
async def test_npm_respects_max_per_query(httpx_mock: HTTPXMock):
    """max_per_query=250 stops after one full page even when more may exist."""
    httpx_mock.add_response(url=_NPM_URL, json={"objects": _full_page()})
    urls = await npm_search(["mcp-server"], max_per_query=250)
    assert len(urls) == 250
    # If a second request were made it would raise (no second mock registered).


@pytest.mark.asyncio
async def test_npm_dedup_across_pages(httpx_mock: HTTPXMock):
    """A URL that appears on multiple pages of the same query is returned once."""
    shared_url = "https://shared.example.com"
    # page1: 249 unique + shared → 250 objects (full page, triggers page 2)
    page1 = [_obj(f"https://pkg{i}.example.com") for i in range(249)] + [_obj(shared_url)]
    # page2: shared again + one new URL → 2 objects (< 250, stops)
    page2 = [_obj(shared_url), _obj("https://unique-page2.example.com")]
    httpx_mock.add_response(url=_NPM_URL, json={"objects": page1})
    httpx_mock.add_response(url=_NPM_URL, json={"objects": page2})
    urls = await npm_search(["mcp-server"])
    assert urls.count(shared_url) == 1
    assert "https://unique-page2.example.com" in urls
