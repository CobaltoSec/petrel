"""Smithery.ai MCP registry discovery — requires SMITHERY_API_KEY."""
from __future__ import annotations
import asyncio
import sys
import httpx

from ..models import SourceResult

_LIST_API = "https://api.smithery.ai/servers"
_PAGE_SIZE = 100
_USER_AGENT = "petrel/0.6.0 (security research)"
_SKIP_HOSTS = frozenset([
    "github.com", "github.io", "gitlab.com", "npmjs.com",
    "npmjs.org", "pypi.org", "docs.", "discord.com",
    "run.tools", "smithery.ai",
])


def _is_deployment_url(url: str) -> bool:
    if not url or not url.startswith(("http://", "https://")):
        return False
    return not any(skip in url for skip in _SKIP_HOSTS)


async def smithery_search(api_key: str | None = None) -> SourceResult:
    """Paginate Smithery.ai registry, extract homepage deployment URLs.

    Requires SMITHERY_API_KEY. Without key: prints warning and returns [].

    Uses the list endpoint (api.smithery.ai/servers) with isDeployed=true.
    Extracts `homepage` field — some point directly to MCP deployment endpoints.
    Skips *.run.tools (Smithery-hosted, require their auth) and code hosting sites.

    Note: most homepages are project websites, not MCP endpoints. Petrel's probe
    step filters out non-MCP hosts downstream, so false candidates are expected.
    """
    import os
    key = api_key or os.getenv("SMITHERY_API_KEY")

    if not key:
        print(
            "[warn] Smithery: SMITHERY_API_KEY not set — skipping (~7,000 servers missed)",
            file=sys.stderr,
        )
        return SourceResult(urls=[])

    headers = {
        "Authorization": f"Bearer {key}",
        "User-Agent": _USER_AGENT,
    }

    urls: list[str] = []

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        headers=headers,
    ) as client:
        page = 1
        while True:
            try:
                resp = await client.get(
                    _LIST_API,
                    params={"page": page, "pageSize": _PAGE_SIZE, "isDeployed": "true"},
                )
                if resp.status_code in (401, 403):
                    print(
                        "[warn] Smithery: authentication failed — check SMITHERY_API_KEY",
                        file=sys.stderr,
                    )
                    return SourceResult(urls=[])
                if resp.status_code == 429:
                    await asyncio.sleep(10.0)
                    continue
                if resp.status_code != 200:
                    break
                data = resp.json()
                servers = data.get("servers", [])
                if not servers:
                    break
                for s in servers:
                    raw = (s.get("homepage") or "").strip()
                    if _is_deployment_url(raw):
                        urls.append(raw)
                pagination = data.get("pagination", {})
                if page >= pagination.get("totalPages", 1):
                    break
                page += 1
            except Exception:
                break

    return SourceResult(urls=list(dict.fromkeys(urls)))
