"""npm registry passive discovery: search packages for MCP server deployment URLs."""
from __future__ import annotations

import asyncio

import httpx

_NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
_USER_AGENT = "petrel/0.3.0 (security research)"

NPM_QUERIES = [
    "mcp-server",
    "modelcontextprotocol",
    "model-context-protocol",
    "mcp-tool",
]

_SKIP_HOSTS = frozenset([
    "github.com",
    "github.io",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "npmjs.org",
    "pypi.org",
    "discord.com",
])


def _is_deployment_url(url: str) -> bool:
    """Return True if url looks like a deployed service, not a source/registry link."""
    if not url or not url.startswith(("http://", "https://")):
        return False
    return not any(skip in url for skip in _SKIP_HOSTS)


async def npm_search(queries: list[str] | None = None) -> list[str]:
    """Search npm registry for MCP-related packages and extract deployment URLs.

    All queries run concurrently. Returns deduplicated deployment URLs from
    package homepage/links fields.
    """
    if queries is None:
        queries = NPM_QUERIES

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:

        async def _fetch_query(query: str) -> list[str]:
            try:
                resp = await client.get(
                    _NPM_SEARCH_URL,
                    params={"text": query, "size": 250},
                )
                if resp.status_code != 200:
                    return []
                urls = []
                for obj in resp.json().get("objects", []):
                    pkg = obj.get("package", {})
                    links = pkg.get("links", {})
                    homepage = (links.get("homepage") or pkg.get("homepage") or "").strip()
                    if _is_deployment_url(homepage):
                        urls.append(homepage)
                return urls
            except Exception:
                return []

        all_results = await asyncio.gather(*[_fetch_query(q) for q in queries])

        seen: set[str] = set()
        result: list[str] = []
        for urls in all_results:
            for url in urls:
                if url not in seen:
                    seen.add(url)
                    result.append(url)

        return result
