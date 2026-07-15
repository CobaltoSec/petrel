"""Censys free API discovery — optional, requires CENSYS_API_ID + CENSYS_API_SECRET."""
from __future__ import annotations

import os

import httpx

_API = "https://search.censys.io/api/v2"
_QUERY = (
    'services.http.response.body: "serverInfo" '
    'and services.http.response.body: "protocolVersion"'
)


async def censys_search(max_results: int = 100) -> list[str]:
    """Search Censys for hosts with MCP-like HTTP responses.

    Returns [] silently if CENSYS_API_ID / CENSYS_API_SECRET are not set.
    Free tier: 250 queries/month — use sparingly.
    """
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return []

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                f"{_API}/hosts/search",
                auth=(api_id, api_secret),
                json={"q": _QUERY, "per_page": min(max_results, 100)},
            )
            if resp.status_code != 200:
                return []

            urls: list[str] = []
            for hit in resp.json().get("result", {}).get("hits", []):
                ip = hit.get("ip", "")
                if not ip:
                    continue
                for svc in hit.get("services", []):
                    port = svc.get("port", 443)
                    scheme = "https" if port in (443, 8443) else "http"
                    urls.append(f"{scheme}://{ip}:{port}")
            return urls
        except Exception:
            return []
