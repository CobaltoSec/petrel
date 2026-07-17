"""Tests for GitHub passive discovery."""
from __future__ import annotations

import asyncio as _asyncio
import re
from unittest.mock import AsyncMock

import pytest
from pytest_httpx import HTTPXMock

from petrel.discovery.github import github_search

_GH_URL = re.compile(r"https://api\.github\.com/search/repositories")


@pytest.mark.asyncio
async def test_github_extracts_homepage_url(httpx_mock: HTTPXMock):
    """Repo with a deployment homepage URL is included in results."""
    httpx_mock.add_response(
        url=_GH_URL,
        json={"items": [{"homepage": "https://my-mcp.vercel.app"}]},
    )
    urls = await github_search(["topic:mcp-server"])
    assert "https://my-mcp.vercel.app" in urls


@pytest.mark.asyncio
async def test_github_skips_source_links(httpx_mock: HTTPXMock):
    """Repos with github.com / npmjs.com homepage are excluded; real deployments are kept."""
    httpx_mock.add_response(
        url=_GH_URL,
        json={
            "items": [
                {"homepage": "https://github.com/user/repo"},
                {"homepage": "https://npmjs.com/package/foo"},
                {"homepage": "https://real-deploy.railway.app"},
            ]
        },
    )
    urls = await github_search(["topic:mcp-server"])
    assert "https://github.com/user/repo" not in urls
    assert "https://npmjs.com/package/foo" not in urls
    assert "https://real-deploy.railway.app" in urls


@pytest.mark.asyncio
async def test_github_skips_empty_homepage(httpx_mock: HTTPXMock):
    """Repos with empty or null homepage are excluded."""
    httpx_mock.add_response(
        url=_GH_URL,
        json={"items": [{"homepage": ""}, {"homepage": None}]},
    )
    urls = await github_search(["topic:mcp-server"])
    assert urls == []


@pytest.mark.asyncio
async def test_github_api_error_returns_empty(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_GH_URL, status_code=403)
    urls = await github_search(["topic:mcp-server"])
    assert urls == []


@pytest.mark.asyncio
async def test_github_uses_token_authorization(httpx_mock: HTTPXMock, monkeypatch):
    """GITHUB_TOKEN env var → Authorization: Bearer header is sent."""
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-xyz")
    httpx_mock.add_response(url=_GH_URL, json={"items": []})

    await github_search(["topic:mcp-server"])

    requests = httpx_mock.get_requests()
    assert any(
        req.headers.get("authorization") == "Bearer test-token-xyz"
        for req in requests
    )


@pytest.mark.asyncio
async def test_github_deduplicates_across_queries(httpx_mock: HTTPXMock, monkeypatch):
    """Same deployment URL from multiple queries appears only once in results."""
    monkeypatch.setattr(_asyncio, "sleep", AsyncMock())
    httpx_mock.add_response(
        url=_GH_URL,
        json={"items": [{"homepage": "https://shared.hf.space"}]},
        is_reusable=True,
    )
    urls = await github_search(["q1", "q2"])
    assert urls.count("https://shared.hf.space") == 1
