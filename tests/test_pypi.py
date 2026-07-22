"""Tests for petrel/discovery/pypi.py — two-phase PyPI discovery."""
from __future__ import annotations
import re
import pytest
import httpx
from pytest_httpx import HTTPXMock

from petrel.discovery.pypi import _is_mcp_package, _is_deployment_url, pypi_search

# ---------------------------------------------------------------------------
# Unit: _is_mcp_package
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("mcp-server", True),
    ("mcp-tool-xyz", True),
    ("my-mcp", True),
    ("mcp_tool", True),
    ("tool_mcp", True),
    ("modelcontext-py", True),
    ("model-context-server", True),
    ("flask", False),
    ("django", False),
    ("requests", False),
    ("mcpython", False),  # no separator
])
def test_is_mcp_package(name: str, expected: bool) -> None:
    assert _is_mcp_package(name) is expected


# ---------------------------------------------------------------------------
# Unit: _is_deployment_url
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://mcp.example.com", True),
    ("http://demo.myserver.io", True),
    ("https://github.com/user/repo", False),
    ("https://user.github.io/proj", False),
    ("https://pkg.readthedocs.io", False),
    ("https://docs.myproject.com", False),
    ("https://pypi.org/project/x", False),
    ("https://npmjs.com/package/x", False),
    ("https://discord.com/channels/x", False),
    ("https://gitlab.com/user/repo", False),
    ("not-a-url", False),
    ("", False),
])
def test_is_deployment_url(url: str, expected: bool) -> None:
    assert _is_deployment_url(url) is expected


# ---------------------------------------------------------------------------
# Integration: pypi_search
# ---------------------------------------------------------------------------

_SIMPLE_RE = re.compile(r"https://pypi\.org/simple/")
_PKG_RE = re.compile(r"https://pypi\.org/pypi/.+/json")


@pytest.mark.asyncio
async def test_pypi_search_home_page(httpx_mock: HTTPXMock) -> None:
    """home_page field is returned when it's a deployment URL."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={"projects": [{"name": "mcp-server-demo"}]},
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://pypi\.org/pypi/mcp-server-demo/json"),
        json={
            "info": {
                "home_page": "https://demo.mcp-server.example.com",
                "project_urls": {},
            }
        },
        is_reusable=True,
    )
    result = await pypi_search()
    assert "https://demo.mcp-server.example.com" in result


@pytest.mark.asyncio
async def test_pypi_search_project_urls_homepage(httpx_mock: HTTPXMock) -> None:
    """project_urls Homepage value is returned when it's a deployment URL."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={"projects": [{"name": "mcp-tool-live"}]},
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://pypi\.org/pypi/mcp-tool-live/json"),
        json={
            "info": {
                "home_page": "",
                "project_urls": {
                    "Homepage": "https://live.mcp-tool.example.com",
                    "Live Demo": "https://demo.mcp-tool.example.com",
                },
            }
        },
        is_reusable=True,
    )
    result = await pypi_search()
    assert "https://live.mcp-tool.example.com" in result
    assert "https://demo.mcp-tool.example.com" in result


@pytest.mark.asyncio
async def test_pypi_search_filters_docs_and_source_links(httpx_mock: HTTPXMock) -> None:
    """github.com and readthedocs links are filtered out."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={"projects": [{"name": "mcp-pkg-filtered"}]},
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://pypi\.org/pypi/mcp-pkg-filtered/json"),
        json={
            "info": {
                "home_page": "https://github.com/user/mcp-pkg-filtered",
                "project_urls": {
                    "Documentation": "https://mcp-pkg-filtered.readthedocs.io",
                    "Source": "https://github.com/user/mcp-pkg-filtered",
                },
            }
        },
        is_reusable=True,
    )
    result = await pypi_search()
    assert result == []


@pytest.mark.asyncio
async def test_pypi_search_handles_package_404(httpx_mock: HTTPXMock) -> None:
    """404 on per-package JSON is handled gracefully; other packages still returned."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={
            "projects": [
                {"name": "mcp-missing"},
                {"name": "mcp-present"},
            ]
        },
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://pypi\.org/pypi/mcp-missing/json"),
        status_code=404,
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://pypi\.org/pypi/mcp-present/json"),
        json={
            "info": {
                "home_page": "https://present.mcp-present.example.com",
                "project_urls": {},
            }
        },
        is_reusable=True,
    )
    result = await pypi_search()
    assert "https://present.mcp-present.example.com" in result


@pytest.mark.asyncio
async def test_pypi_search_returns_empty_on_simple_index_failure(httpx_mock: HTTPXMock) -> None:
    """500 from Simple index returns []."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        status_code=500,
        is_reusable=True,
    )
    result = await pypi_search()
    assert result == []


@pytest.mark.asyncio
async def test_pypi_search_deduplicates_urls(httpx_mock: HTTPXMock) -> None:
    """Same URL appearing in home_page and project_urls is deduplicated."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={"projects": [{"name": "mcp-dedup"}]},
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://pypi\.org/pypi/mcp-dedup/json"),
        json={
            "info": {
                "home_page": "https://dedup.example.com",
                "project_urls": {
                    "Homepage": "https://dedup.example.com",
                },
            }
        },
        is_reusable=True,
    )
    result = await pypi_search()
    assert result.count("https://dedup.example.com") == 1


@pytest.mark.asyncio
async def test_pypi_chunked_gather(httpx_mock: HTTPXMock) -> None:
    """120 MCP packages are processed correctly across multiple chunks of 50."""
    packages = [f"mcp-server-{i}" for i in range(120)]
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={"projects": [{"name": p} for p in packages]},
        is_reusable=True,
    )
    httpx_mock.add_response(
        url=_PKG_RE,
        json={
            "info": {
                "home_page": "https://chunked-test.example.com",
                "project_urls": {},
            }
        },
        is_reusable=True,
    )
    result = await pypi_search()
    # 120 packages all return same URL → dedup to 1
    assert result == ["https://chunked-test.example.com"]


@pytest.mark.asyncio
async def test_pypi_search_skips_non_mcp_packages(httpx_mock: HTTPXMock) -> None:
    """Packages without MCP substrings are filtered before phase 2."""
    httpx_mock.add_response(
        url=_SIMPLE_RE,
        json={
            "projects": [
                {"name": "flask"},
                {"name": "django"},
                {"name": "requests"},
            ]
        },
        is_reusable=True,
    )
    # No per-package requests should be made
    result = await pypi_search()
    assert result == []
