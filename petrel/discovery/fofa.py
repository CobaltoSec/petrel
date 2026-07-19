"""FOFA internet scanner discovery — optional, requires FOFA_EMAIL + FOFA_KEY."""
from __future__ import annotations
import base64
import os

import httpx

_API = "https://fofa.info/api/v1/search/all"
_QUERY = 'body="2024-11-05"'


async def fofa_search(max_results: int = 500) -> list[str]:
    """Search FOFA for hosts with MCP-like HTTP responses.

    Returns [] silently if FOFA_EMAIL / FOFA_KEY are not set.
    Free tier: 10,000 results/month.
    """
    email = os.getenv("FOFA_EMAIL")
    key = os.getenv("FOFA_KEY")
    if not email or not key:
        return []

    qb64 = base64.b64encode(_QUERY.encode()).decode()

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(
                _API,
                params={
                    "email": email,
                    "key": key,
                    "qbase64": qb64,
                    "size": min(max_results, 10000),
                    "fields": "ip,port,protocol",
                    "full": "false",
                },
            )
            if resp.status_code != 200:
                return []
            urls: list[str] = []
            for item in resp.json().get("results", []):
                # item = [ip, port, protocol]
                if len(item) < 3:
                    continue
                ip, port, proto = str(item[0]), str(item[1]), str(item[2])
                scheme = "https" if proto == "https" or port in ("443", "8443") else "http"
                urls.append(f"{scheme}://{ip}:{port}")
            return list(dict.fromkeys(urls))
        except Exception:
            return []
