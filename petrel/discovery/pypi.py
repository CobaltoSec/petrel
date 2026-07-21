"""PyPI package registry discovery — two-phase: Simple index + per-package JSON."""
from __future__ import annotations
import asyncio
import httpx

from ..models import SourceResult

_SIMPLE_URL = "https://pypi.org/simple/"
_PKG_JSON_URL = "https://pypi.org/pypi/{}/json"
_USER_AGENT = "petrel/0.5.0 (security research)"
_MCP_SUBSTRINGS = ["mcp-", "-mcp", "mcp_", "_mcp", "modelcontext", "model-context"]
_SKIP_HOSTS = frozenset([
    "github.com", "github.io", "gitlab.com",
    "readthedocs", "docs.", "pypi.org", "npmjs.com", "discord.com",
])


def _is_deployment_url(url: str) -> bool:
    if not url or not url.startswith(("http://", "https://")):
        return False
    return not any(skip in url for skip in _SKIP_HOSTS)


def _is_mcp_package(name: str) -> bool:
    n = name.lower()
    return any(sub in n for sub in _MCP_SUBSTRINGS)


async def pypi_search() -> SourceResult:
    """Two-phase PyPI discovery: filter package names → extract deployment URLs."""
    async with httpx.AsyncClient(
        timeout=60.0,
        headers={
            "Accept": "application/vnd.pypi.simple.v1+json",
            "User-Agent": _USER_AGENT,
        },
    ) as client:
        try:
            resp = await client.get(_SIMPLE_URL)
            if resp.status_code != 200:
                return SourceResult(urls=[])
            candidates = [
                p["name"]
                for p in resp.json().get("projects", [])
                if _is_mcp_package(p.get("name", ""))
            ]
        except Exception as e:
            return SourceResult(urls=[], error=str(e))

    sem = asyncio.Semaphore(10)

    async def _fetch_pkg(name: str) -> list[str]:
        async with sem:
            async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": _USER_AGENT}) as c:
                try:
                    r = await c.get(_PKG_JSON_URL.format(name))
                    if r.status_code != 200:
                        return []
                    info = r.json().get("info", {})
                    found: list[str] = []
                    home = (info.get("home_page") or "").strip()
                    if _is_deployment_url(home):
                        found.append(home)
                    for url_val in (info.get("project_urls") or {}).values():
                        url_str = (url_val or "").strip()
                        if _is_deployment_url(url_str) and url_str not in found:
                            found.append(url_str)
                    return found
                except Exception:
                    return []

    batches = await asyncio.gather(*[_fetch_pkg(n) for n in candidates])
    all_urls = [u for batch in batches for u in batch]
    return SourceResult(urls=list(dict.fromkeys(all_urls)))
