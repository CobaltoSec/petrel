"""GitHub passive discovery: search repos for MCP server deployment URLs."""
from __future__ import annotations

import asyncio
import os

import httpx

_API_BASE = "https://api.github.com"
_USER_AGENT = "petrel/0.3.0 (security research)"

GITHUB_QUERIES = [
    "topic:mcp-server",
    '"mcp-server" in:name',
    '"model-context-protocol" in:readme',
    '"mcp_server" in:name',
]

_SKIP_HOSTS = frozenset([
    "github.com",
    "github.io",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "npmjs.org",
    "pypi.org",
    "pkg.go.dev",
    "readthedocs",
    "docs.",
    "discord.com",
])


def _is_deployment_url(url: str) -> bool:
    """Return True if url looks like a deployed service, not a source/docs link."""
    if not url or not url.startswith(("http://", "https://")):
        return False
    return not any(skip in url for skip in _SKIP_HOSTS)


async def github_search(
    queries: list[str] | None = None,
    token: str | None = None,
) -> list[str]:
    """Search GitHub repos for MCP server deployment URLs via homepage fields.

    GITHUB_TOKEN env var used if token not provided (raises rate limit 10→30 req/min).
    Returns deduplicated deployment URLs extracted from repo homepage fields.
    """
    if queries is None:
        queries = GITHUB_QUERIES
    if token is None:
        token = os.getenv("GITHUB_TOKEN")

    headers: dict[str, str] = {
        "User-Agent": _USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    delay = 2.0 if token else 6.0

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        headers=headers,
    ) as client:

        async def _fetch_query(query: str) -> list[str]:
            try:
                resp = await client.get(
                    f"{_API_BASE}/search/repositories",
                    params={"q": query, "sort": "stars", "per_page": 100},
                )
                if resp.status_code != 200:
                    return []
                urls = []
                for repo in resp.json().get("items", []):
                    homepage = (repo.get("homepage") or "").strip()
                    if _is_deployment_url(homepage):
                        urls.append(homepage)
                return urls
            except Exception:
                return []

        seen: set[str] = set()
        result: list[str] = []
        for i, query in enumerate(queries):
            if i > 0:
                await asyncio.sleep(delay)
            for url in await _fetch_query(query):
                if url not in seen:
                    seen.add(url)
                    result.append(url)

        return result
