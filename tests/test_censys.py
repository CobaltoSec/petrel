"""Tests for Censys discovery — cursor pagination (DISC-008)."""
from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from petrel.discovery.censys import censys_search

_CENSYS_RE = re.compile(r"https://search\.censys\.io/api/v2/hosts/search")

# Sample hits
_HIT_A = {"ip": "1.2.3.4", "services": [{"port": 443}]}
_HIT_B = {"ip": "5.6.7.8", "services": [{"port": 8080}]}
_HIT_C = {"ip": "9.9.9.9", "services": [{"port": 443}]}


def _page(hits: list, cursor: str | None = None) -> dict:
    """Build a Censys /hosts/search JSON response."""
    return {
        "result": {
            "hits": hits,
            "total": 500,
            "links": {"next": cursor},
        }
    }


@pytest.mark.asyncio
async def test_no_credentials_returns_empty(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    result = await censys_search()
    assert result == []


@pytest.mark.asyncio
async def test_single_page_no_cursor(httpx_mock: HTTPXMock, monkeypatch):
    """Single page with no cursor — returns hits, exactly one request made."""
    monkeypatch.setenv("CENSYS_API_ID", "test_id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test_secret")
    httpx_mock.add_response(
        url=_CENSYS_RE,
        json=_page([_HIT_A, _HIT_B], cursor=None),
        is_reusable=True,
    )
    urls = await censys_search()
    assert "https://1.2.3.4:443" in urls
    assert "http://5.6.7.8:8080" in urls
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_two_pages_combined(httpx_mock: HTTPXMock, monkeypatch):
    """Two pages: first response has cursor → second request made, results combined."""
    monkeypatch.setenv("CENSYS_API_ID", "test_id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test_secret")
    httpx_mock.add_response(
        url=_CENSYS_RE,
        json=_page([_HIT_A], cursor="cursor_page2"),
    )
    httpx_mock.add_response(
        url=_CENSYS_RE,
        json=_page([_HIT_B], cursor=None),
    )
    urls = await censys_search()
    assert "https://1.2.3.4:443" in urls
    assert "http://5.6.7.8:8080" in urls
    assert len(httpx_mock.get_requests()) == 2


@pytest.mark.asyncio
async def test_stops_at_max_results(httpx_mock: HTTPXMock, monkeypatch):
    """Stops after the first page when max_results is already satisfied."""
    monkeypatch.setenv("CENSYS_API_ID", "test_id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test_secret")
    # First page yields 2 URLs with a cursor — max_results=2 means loop won't fire
    httpx_mock.add_response(
        url=_CENSYS_RE,
        json=_page([_HIT_A, _HIT_B], cursor="cursor_page2"),
        is_reusable=True,
    )
    urls = await censys_search(max_results=2)
    assert len(urls) <= 2
    # Only ONE request made — the while condition (len < max_results) was False
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_non_200_page2_returns_partial(httpx_mock: HTTPXMock, monkeypatch):
    """Non-200 on page 2 — partial results from page 1 are returned, no exception."""
    monkeypatch.setenv("CENSYS_API_ID", "test_id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test_secret")
    httpx_mock.add_response(
        url=_CENSYS_RE,
        json=_page([_HIT_A], cursor="cursor_page2"),
    )
    httpx_mock.add_response(
        url=_CENSYS_RE,
        status_code=429,
    )
    urls = await censys_search()
    # Page 1 results must be present despite page 2 failure
    assert "https://1.2.3.4:443" in urls
    assert len(urls) == 1
