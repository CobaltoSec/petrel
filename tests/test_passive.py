"""Tests for passive discovery: crt.sh, HuggingFace, Censys."""
from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from petrel.discovery.censys import censys_search
from petrel.discovery.passive import crtsh_search, hf_spaces_search


# --- crt.sh ---


@pytest.mark.asyncio
async def test_crtsh_no_domain_filter(httpx_mock: HTTPXMock):
    """D2b: domains without the keyword in their name are still returned."""
    httpx_mock.add_response(
        url=re.compile(r"https://crt\.sh/"),
        json=[
            {"name_value": "mcp-server.example.com"},
            {"name_value": "tools.example.com"},  # no "mcp" in name
        ],
        is_reusable=True,
    )
    results = await crtsh_search(["mcp"])
    assert "tools.example.com" in results
    assert "mcp-server.example.com" in results


@pytest.mark.asyncio
async def test_crtsh_deduplicates_across_keywords(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"https://crt\.sh/"),
        json=[{"name_value": "shared.example.com"}],
        is_reusable=True,
    )
    results = await crtsh_search(["mcp", "mcp-server"])
    assert results.count("shared.example.com") == 1


@pytest.mark.asyncio
async def test_crtsh_strips_wildcard_prefix(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"https://crt\.sh/"),
        json=[{"name_value": "*.wildcard.io\nregular.io"}],
        is_reusable=True,
    )
    results = await crtsh_search(["mcp"])
    assert "wildcard.io" in results
    assert "*.wildcard.io" not in results


@pytest.mark.asyncio
async def test_crtsh_partial_keyword_failure(httpx_mock: HTTPXMock):
    """If one keyword request fails, the rest still contribute results."""
    httpx_mock.add_response(url=re.compile(r"https://crt\.sh/"), status_code=500)
    httpx_mock.add_response(
        url=re.compile(r"https://crt\.sh/"),
        json=[{"name_value": "good.example.com"}],
    )
    results = await crtsh_search(["fail", "ok"])
    assert "good.example.com" in results


@pytest.mark.asyncio
async def test_crtsh_empty_response(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"https://crt\.sh/"),
        json=[],
        is_reusable=True,
    )
    results = await crtsh_search(["mcp"])
    assert results == []


# --- HuggingFace ---


@pytest.mark.asyncio
async def test_hf_multi_queries_dedup(httpx_mock: HTTPXMock):
    """Same space returned by multiple queries appears only once."""
    httpx_mock.add_response(
        url=re.compile(r"https://huggingface\.co/api/spaces"),
        json=[{"id": "user/my-mcp-server"}, {"id": "other/model-context"}],
        is_reusable=True,
    )
    urls = await hf_spaces_search(["q1", "q2"])
    assert urls.count("https://user-my-mcp-server.hf.space") == 1
    assert "https://other-model-context.hf.space" in urls


@pytest.mark.asyncio
async def test_hf_pagination(httpx_mock: HTTPXMock):
    """Full page triggers a second request; partial page stops pagination."""
    full_page = [{"id": f"user/space-{i}"} for i in range(500)]
    partial_page = [{"id": "user/last-space"}]

    # Sequential loop — FIFO serving works correctly here
    httpx_mock.add_response(
        url=re.compile(r"https://huggingface\.co/api/spaces"),
        json=full_page,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://huggingface\.co/api/spaces"),
        json=partial_page,
    )

    urls = await hf_spaces_search(["mcp-server"])
    assert len(urls) == 501
    assert "https://user-last-space.hf.space" in urls


@pytest.mark.asyncio
async def test_hf_underscore_to_dash_in_slug(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"https://huggingface\.co/api/spaces"),
        json=[{"id": "my_user/my_space_name"}],
    )
    urls = await hf_spaces_search(["q"])
    assert urls == ["https://my-user-my-space-name.hf.space"]


@pytest.mark.asyncio
async def test_hf_partial_query_failure(httpx_mock: HTTPXMock):
    """If one query request fails, the other still contributes results."""
    httpx_mock.add_response(
        url=re.compile(r"https://huggingface\.co/api/spaces"),
        status_code=500,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://huggingface\.co/api/spaces"),
        json=[{"id": "user/good-space"}],
    )
    urls = await hf_spaces_search(["fail", "ok"])
    assert "https://user-good-space.hf.space" in urls


# --- Censys ---


@pytest.mark.asyncio
async def test_censys_no_credentials_returns_empty(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)

    result = await censys_search()
    assert result == []


@pytest.mark.asyncio
async def test_censys_with_credentials(httpx_mock: HTTPXMock, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")

    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={
            "result": {
                "hits": [
                    {"ip": "1.2.3.4", "services": [{"port": 443}, {"port": 8080}]},
                    {"ip": "5.6.7.8", "services": [{"port": 443}]},
                ]
            }
        },
    )

    urls = await censys_search()
    assert "https://1.2.3.4:443" in urls
    assert "http://1.2.3.4:8080" in urls
    assert "https://5.6.7.8:443" in urls


@pytest.mark.asyncio
async def test_censys_api_error_returns_empty(httpx_mock: HTTPXMock, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")

    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        status_code=403,
    )

    result = await censys_search()
    assert result == []
