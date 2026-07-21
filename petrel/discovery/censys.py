"""Censys free API discovery — optional, requires CENSYS_API_ID + CENSYS_API_SECRET."""
from __future__ import annotations

import os

import httpx

from ..models import SourceResult

_API = "https://search.censys.io/api/v2"
_QUERY = 'services.http.response.body: "2024-11-05"'


def _extract_urls(hits: list, urls: list[str]) -> None:
    """Append URLs extracted from Censys hit objects into *urls*."""
    for hit in hits:
        ip = hit.get("ip", "")
        if not ip:
            continue
        for svc in hit.get("services", []):
            port = svc.get("port", 443)
            scheme = "https" if port in (443, 8443) else "http"
            urls.append(f"{scheme}://{ip}:{port}")


async def censys_search(max_results: int = 500) -> SourceResult:
    """Search Censys for hosts with MCP-like HTTP responses.

    Paginates via cursor until *max_results* are collected or no more pages exist.
    Returns SourceResult(urls=[]) silently if CENSYS_API_ID / CENSYS_API_SECRET are not set.
    Free tier: 250 queries/month — use sparingly (5 pages max at default).
    """
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return SourceResult(urls=[])

    urls: list[str] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # First page — always includes the query
            resp = await client.post(
                f"{_API}/hosts/search",
                auth=(api_id, api_secret),
                json={"q": _QUERY, "per_page": 100},
            )
            if resp.status_code != 200:
                return SourceResult(urls=[])

            result = resp.json().get("result", {})
            _extract_urls(result.get("hits", []), urls)
            cursor: str | None = result.get("links", {}).get("next")

            # Subsequent pages — only cursor needed, no q
            while cursor and len(urls) < max_results:
                resp = await client.post(
                    f"{_API}/hosts/search",
                    auth=(api_id, api_secret),
                    json={"cursor": cursor, "per_page": 100},
                )
                if resp.status_code != 200:
                    break
                result = resp.json().get("result", {})
                _extract_urls(result.get("hits", []), urls)
                cursor = result.get("links", {}).get("next")

            return SourceResult(urls=urls[:max_results])

        except Exception as e:
            return SourceResult(urls=urls[:max_results], error=str(e))
