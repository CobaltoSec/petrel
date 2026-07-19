"""Smithery.ai MCP registry discovery — no API key required."""
from __future__ import annotations
import httpx

_API = "https://smithery.ai/api/v1/servers"
_PAGE_SIZE = 100
_USER_AGENT = "petrel/0.4.0 (security research)"
_SKIP_HOSTS = frozenset([
    "github.com", "github.io", "gitlab.com", "npmjs.com",
    "npmjs.org", "pypi.org", "docs.", "discord.com",
])


def _is_deployment_url(url: str) -> bool:
    if not url or not url.startswith(("http://", "https://")):
        return False
    return not any(skip in url for skip in _SKIP_HOSTS)


async def smithery_search() -> list[str]:
    """Paginate Smithery.ai registry, extract deployment URLs."""
    urls: list[str] = []
    page = 1
    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        while True:
            try:
                resp = await client.get(
                    _API,
                    params={"page": page, "pageSize": _PAGE_SIZE},
                )
                if resp.status_code != 200:
                    break
                data = resp.json()
                servers = data.get("servers", [])
                if not servers:
                    break
                for s in servers:
                    # Try fields in priority order
                    for field in ("homepage", "deploymentUrl", "url"):
                        raw = (s.get(field) or "").strip()
                        if _is_deployment_url(raw):
                            urls.append(raw)
                            break
                total = data.get("total", 0)
                if page * _PAGE_SIZE >= total:
                    break
                page += 1
            except Exception:
                break
    return list(dict.fromkeys(urls))  # deduplicate, preserve order
