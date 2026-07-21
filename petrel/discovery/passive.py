"""Passive discovery: crt.sh and HuggingFace Spaces (no API key required)."""
from __future__ import annotations

import asyncio
import re

import httpx

from ..models import SourceResult

CRTSH_KEYWORDS = ["mcp", "mcp-server", "modelcontext", "llm-server"]
HF_QUERIES = ["mcp-server", "mcp server", "model-context-protocol", "mcp tool"]
_HF_PAGE_SIZE = 500
_HF_MAX_PAGES = 10  # safety cap: 5 000 results per query max
_USER_AGENT = "petrel/0.3.0 (security research)"
_CRTSH_RETRIES = 2  # up to 3 total attempts per keyword

_MCP_PLATFORM_SUFFIXES = (
    ".hf.space", ".vercel.app", ".railway.app", ".onrender.com",
    ".fly.dev", ".fly.io", ".modal.run", ".replit.dev",
    ".workers.dev", ".netlify.app", ".render.com", ".glitch.me",
    ".modal.run", ".amazonaws.com", ".run.app", ".cloudfunctions.net",
)


def _is_likely_mcp_domain(domain: str) -> bool:
    """Return True if domain looks like a real MCP server deployment.

    Applied only to the generic 'mcp' keyword to reduce noise from
    consulting firms, certifications, and media protocols.
    """
    d = domain.lower()
    if any(d.endswith(s) for s in _MCP_PLATFORM_SUFFIXES):
        return True
    # "modelcontext" or "model-context" anywhere in the domain
    if re.search(r'(?:modelcontext|model-context)', d):
        return True
    # "mcp" as a complete dot-separated label, or as an interior hyphen-token
    # (not as a trailing hyphen suffix directly before the TLD dot)
    return bool(re.search(r'(?:^|\.)mcp[\.\-]|(?:-)mcp-', d))


async def crtsh_search(keywords: list[str] | None = None) -> SourceResult:
    """Search certificate transparency logs across multiple keywords.

    No domain-name filtering — fingerprinting confirms if it's actually MCP.
    Retries up to 2 times on timeout or 429.
    """
    if keywords is None:
        keywords = CRTSH_KEYWORDS

    async with httpx.AsyncClient(
        timeout=60.0,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:

        async def _fetch(kw: str) -> set[str]:
            for attempt in range(_CRTSH_RETRIES + 1):
                try:
                    resp = await client.get(
                        "https://crt.sh/",
                        params={"q": kw, "output": "json"},
                    )
                    if resp.status_code == 429 and attempt < _CRTSH_RETRIES:
                        await asyncio.sleep(5.0)
                        continue
                    if resp.status_code != 200:
                        return set()
                    found: set[str] = set()
                    for entry in resp.json():
                        for domain in entry.get("name_value", "").split("\n"):
                            domain = domain.strip().lstrip("*.")
                            if domain and "." in domain:
                                found.add(domain)
                    return found
                except (httpx.TimeoutException, httpx.NetworkError):
                    if attempt < _CRTSH_RETRIES:
                        await asyncio.sleep(2.0**attempt)
                        continue
                    return set()
            return set()

        all_domains: set[str] = set()
        try:
            for i, kw in enumerate(keywords):
                if i > 0:
                    await asyncio.sleep(1.0)  # avoid crt.sh rate limiting
                found = await _fetch(kw)
                # Pre-filter generic 'mcp' keyword: only keep domains that look like MCP deployments
                if kw == "mcp":
                    found = {d for d in found if _is_likely_mcp_domain(d)}
                all_domains.update(found)
            return SourceResult(urls=sorted(all_domains))
        except Exception as e:
            return SourceResult(urls=sorted(all_domains), error=str(e))


async def hf_spaces_search(queries: list[str] | None = None) -> SourceResult:
    """Find MCP server spaces on HuggingFace across multiple queries with pagination."""
    if queries is None:
        queries = HF_QUERIES

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:

        async def _fetch_query(query: str) -> list[tuple[str, str]]:
            """Returns [(space_id, url), ...]."""
            results: list[tuple[str, str]] = []
            for page in range(_HF_MAX_PAGES):
                try:
                    resp = await client.get(
                        "https://huggingface.co/api/spaces",
                        params={
                            "search": query,
                            "limit": _HF_PAGE_SIZE,
                            "sort": "likes",
                            "skip": page * _HF_PAGE_SIZE,
                        },
                    )
                    if resp.status_code != 200:
                        break
                    batch = resp.json()
                    if not batch:
                        break
                    for space in batch:
                        space_id = space.get("id", "")
                        if not space_id or "/" not in space_id:
                            continue
                        owner, name = space_id.split("/", 1)
                        slug = f"{owner}-{name}".lower().replace("_", "-")
                        results.append((space_id, f"https://{slug}.hf.space"))
                    if len(batch) < _HF_PAGE_SIZE:
                        break
                except Exception:
                    break
            return results

        all_pages = await asyncio.gather(*[_fetch_query(q) for q in queries])

        seen: set[str] = set()
        urls: list[str] = []
        for items in all_pages:
            for space_id, url in items:
                if space_id not in seen:
                    seen.add(space_id)
                    urls.append(url)
        return SourceResult(urls=urls)
