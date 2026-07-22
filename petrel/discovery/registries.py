"""MCP registry discovery — glama.ai and pulsemcp.com."""
from __future__ import annotations

import asyncio
import re
import sys

import httpx

from ..models import SourceResult

_USER_AGENT = "petrel/0.6.0 (security research)"
_MAX_RESULTS = 500

_SKIP_HOSTS = frozenset([
    "github.com", "github.io", "gitlab.com", "npmjs.com",
    "npmjs.org", "pypi.org", "discord.com", "twitter.com",
    "x.com", "linkedin.com", "youtube.com", "medium.com",
    "glama.ai", "pulsemcp.com", "smithery.ai", "run.tools",
    "docs.", "blog.", "notion.so",
])

_GLAMA_API = "https://glama.ai/api/mcp/v1/servers"
_GLAMA_HTML = "https://glama.ai/mcp/servers"
_GLAMA_PAGE_SIZE = 50

_PULSEMCP_API = "https://api.pulsemcp.com/v0beta/servers"
_PULSEMCP_PAGE_SIZE = 100


def _is_deployment_url(url: str) -> bool:
    """Return True if *url* looks like a live deployment endpoint."""
    if not url or not url.startswith(("http://", "https://")):
        return False
    return not any(skip in url for skip in _SKIP_HOSTS)


def _extract_url_from_server(server: dict) -> str | None:
    """Try common field names for a deployment URL in a server dict."""
    for field in ("url", "endpoint", "homepage", "websiteUrl", "website_url", "deploymentUrl"):
        raw = (server.get(field) or "").strip()
        if raw and _is_deployment_url(raw):
            return raw
    return None


async def glama_search() -> SourceResult:
    """Discover MCP servers listed on glama.ai.

    Tries the JSON API first (paginated with cursor). Falls back to basic
    HTML scraping if the API returns 404 or non-JSON. Returns SourceResult
    with source="glama"; on any unrecoverable error returns empty list.
    """
    urls: list[str] = []
    warnings: list[str] = []

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        # --- Try JSON API ---
        api_ok = False
        cursor: str | None = None

        while len(urls) < _MAX_RESULTS:
            params: dict = {"first": _GLAMA_PAGE_SIZE}
            if cursor:
                params["after"] = cursor

            try:
                resp = await client.get(_GLAMA_API, params=params)
            except Exception as exc:
                warnings.append(f"glama API request failed: {exc}")
                break

            if resp.status_code == 404:
                # API endpoint doesn't exist — fall through to HTML scraping
                break

            if resp.status_code != 200:
                warnings.append(f"glama API returned HTTP {resp.status_code}")
                break

            try:
                data = resp.json()
            except Exception:
                # Not JSON — fall through to HTML scraping
                break

            api_ok = True

            # Support both list-at-root and wrapped {"servers": [...]} shapes
            if isinstance(data, list):
                servers = data
                next_cursor = None
            elif isinstance(data, dict):
                # Try common envelope keys
                servers = (
                    data.get("servers")
                    or data.get("data")
                    or data.get("items")
                    or data.get("nodes")
                    or []
                )
                # Try common pagination keys
                page_info = data.get("pageInfo") or data.get("pagination") or {}
                next_cursor = (
                    page_info.get("endCursor")
                    or page_info.get("nextCursor")
                    or page_info.get("next_cursor")
                    or data.get("nextCursor")
                    or data.get("next_cursor")
                )
            else:
                break

            for s in servers:
                if not isinstance(s, dict):
                    continue
                url = _extract_url_from_server(s)
                if url:
                    urls.append(url)

            if not servers or not next_cursor:
                break
            cursor = next_cursor

        # --- HTML fallback ---
        if not api_ok:
            try:
                resp = await client.get(_GLAMA_HTML)
                if resp.status_code == 200:
                    # Extract https:// URLs that look like deployment endpoints
                    candidates = re.findall(r'https?://[^\s\'"<>]+', resp.text)
                    for raw in candidates:
                        # Strip trailing punctuation
                        raw = raw.rstrip('.,;:)')
                        if _is_deployment_url(raw):
                            urls.append(raw)
            except Exception as exc:
                warnings.append(f"glama HTML scrape failed: {exc}")
                print(f"[warn] glama: HTML fallback failed: {exc}", file=sys.stderr)

    deduped = list(dict.fromkeys(urls))[:_MAX_RESULTS]
    return SourceResult(
        urls=deduped,
        warnings=warnings if warnings else None,
    )


async def pulsemcp_search() -> SourceResult:
    """Discover MCP servers listed on pulsemcp.com.

    Uses the public v0beta API with cursor-based pagination. Returns
    SourceResult with source="pulsemcp"; on error returns empty list.
    """
    urls: list[str] = []
    warnings: list[str] = []

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        cursor: str | None = None

        while len(urls) < _MAX_RESULTS:
            params: dict = {"count_per_page": _PULSEMCP_PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor

            try:
                resp = await client.get(_PULSEMCP_API, params=params)
            except Exception as exc:
                warnings.append(f"pulsemcp request failed: {exc}")
                print(f"[warn] pulsemcp: request failed: {exc}", file=sys.stderr)
                break

            if resp.status_code != 200:
                warnings.append(f"pulsemcp returned HTTP {resp.status_code}")
                break

            try:
                data = resp.json()
            except Exception as exc:
                warnings.append(f"pulsemcp non-JSON response: {exc}")
                break

            # Support both list-at-root and wrapped shapes
            if isinstance(data, list):
                servers = data
                next_cursor = None
            elif isinstance(data, dict):
                servers = (
                    data.get("servers")
                    or data.get("data")
                    or data.get("items")
                    or data.get("results")
                    or []
                )
                next_cursor = (
                    data.get("next_cursor")
                    or data.get("nextCursor")
                    or data.get("cursor")
                )
            else:
                break

            for s in servers:
                if not isinstance(s, dict):
                    continue
                url = _extract_url_from_server(s)
                if url:
                    urls.append(url)
                else:
                    # pulsemcp sometimes exposes source_code_url but the actual
                    # deployment URL is under a different key — try a few more
                    for field in ("source_code_url", "github_url", "repo_url"):
                        raw = (s.get(field) or "").strip()
                        if raw and _is_deployment_url(raw):
                            urls.append(raw)
                            break

            if not servers or not next_cursor:
                break
            cursor = next_cursor

    deduped = list(dict.fromkeys(urls))[:_MAX_RESULTS]
    return SourceResult(
        urls=deduped,
        warnings=warnings if warnings else None,
    )


async def registries_search() -> list[SourceResult]:
    """Run glama and pulsemcp discovery in parallel, merging results.

    Exceptions from individual sources are swallowed — a partial failure
    does not abort the overall discovery run.
    """
    results = await asyncio.gather(
        glama_search(),
        pulsemcp_search(),
        return_exceptions=True,
    )
    out: list[str] = []
    for r in results:
        if isinstance(r, Exception):
            print(f"[warn] registries: source raised: {r}", file=sys.stderr)
            continue
        out.extend(r)

    return SourceResult(urls=list(dict.fromkeys(out)))
