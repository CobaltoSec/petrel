"""Shodan internet scanner discovery — optional, requires SHODAN_API_KEY."""
from __future__ import annotations

import os

import httpx

from ..models import SourceResult

_API = "https://api.shodan.io/shodan/host/search"
_QUERY = 'http.html:"2024-11-05"'
_MAX_PAGES = 10  # 10 pages × 100 results = 1 000 hosts maximum


def _extract_urls(matches: list) -> list[str]:
    """Extract URLs from Shodan host match objects.

    Prefers the first hostname (virtual-host aware) over raw IP.
    Note: when probing by IP directly, virtual hosting may cause the server
    response to differ from what Shodan indexed for that port.
    """
    urls: list[str] = []
    for match in matches:
        ip = match.get("ip_str", "")
        port = match.get("port", 80)
        # Prefer hostname so probes hit the right virtual host
        hostnames = match.get("hostnames") or []
        host = hostnames[0] if hostnames else ip
        if not host:
            continue
        scheme = "https" if port == 443 else "http"
        urls.append(f"{scheme}://{host}:{port}")
    return urls


async def shodan_search(max_results: int = 1000) -> SourceResult:
    """Search Shodan for hosts with MCP-like HTTP responses.

    Paginates via page=N (1-indexed, 100 results/page) until *max_results* are
    collected or *_MAX_PAGES* pages are consumed.
    Returns SourceResult(urls=[]) silently if SHODAN_API_KEY is not set.
    Paid plan required for full pagination (free accounts: first page only).
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return SourceResult(urls=[])

    urls: list[str] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            for page in range(1, _MAX_PAGES + 1):
                resp = await client.get(
                    _API,
                    params={
                        "query": _QUERY,
                        "key": api_key,
                        "page": page,
                    },
                )
                if resp.status_code in (401, 402):
                    # 401 = invalid credentials, 402 = plan upgrade required
                    return SourceResult(
                        urls=urls,
                        error=f"Shodan API error {resp.status_code}: {resp.text[:200]}",
                    )
                if resp.status_code == 429:
                    # Rate limited — return what we have so far
                    return SourceResult(urls=urls, error="Shodan rate limit hit (429)")
                if resp.status_code != 200:
                    return SourceResult(
                        urls=urls,
                        error=f"Shodan HTTP {resp.status_code}",
                    )

                data = resp.json()
                matches = data.get("matches", [])
                if not matches:
                    break

                urls.extend(_extract_urls(matches))
                if len(urls) >= max_results:
                    break

            return SourceResult(urls=list(dict.fromkeys(urls))[:max_results])

        except Exception as e:
            return SourceResult(urls=urls[:max_results], error=str(e))
