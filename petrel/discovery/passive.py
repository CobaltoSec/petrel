"""Passive discovery: crt.sh and HuggingFace Spaces (no API key required)."""
from __future__ import annotations

import asyncio

import httpx

CRTSH_KEYWORDS = ["mcp", "mcp-server", "modelcontext", "llm-server"]
HF_QUERIES = ["mcp-server", "mcp server", "model-context-protocol", "mcp tool"]
_HF_PAGE_SIZE = 500
_HF_MAX_PAGES = 10  # safety cap: 5 000 results per query max


async def crtsh_search(keywords: list[str] | None = None) -> list[str]:
    """Search certificate transparency logs across multiple keywords.

    No domain-name filtering — fingerprinting confirms if it's actually MCP.
    """
    if keywords is None:
        keywords = CRTSH_KEYWORDS

    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:

        async def _fetch(kw: str) -> set[str]:
            try:
                resp = await client.get(
                    "https://crt.sh/",
                    params={"q": kw, "output": "json"},
                )
                if resp.status_code != 200:
                    return set()
                found: set[str] = set()
                for entry in resp.json():
                    for domain in entry.get("name_value", "").split("\n"):
                        domain = domain.strip().lstrip("*.")
                        if domain and "." in domain:
                            found.add(domain)
                return found
            except Exception:
                return set()

        all_domains: set[str] = set()
        for i, kw in enumerate(keywords):
            if i > 0:
                await asyncio.sleep(1.0)  # avoid crt.sh rate limiting
            found = await _fetch(kw)
            all_domains.update(found)
        return sorted(all_domains)


async def hf_spaces_search(queries: list[str] | None = None) -> list[str]:
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
        return urls
