"""FOFA internet scanner discovery — optional, requires FOFA_EMAIL + FOFA_KEY."""
from __future__ import annotations
import base64
import os
import re

import httpx

from ..models import SourceResult

_IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

_API = "https://fofa.info/api/v1/search/all"
_QUERY = 'body="2024-11-05"'


async def fofa_search(max_results: int = 500) -> SourceResult:
    """Search FOFA for hosts with MCP-like HTTP responses.

    Returns SourceResult(urls=[]) silently if FOFA_EMAIL / FOFA_KEY are not set.
    Free tier: 10,000 results/month.
    """
    email = os.getenv("FOFA_EMAIL")
    key = os.getenv("FOFA_KEY")
    if not email or not key:
        return SourceResult(urls=[])

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
                    "fields": "host,ip,port,protocol",
                    "full": "false",
                },
            )
            if resp.status_code != 200:
                return SourceResult(urls=[])
            urls: list[str] = []
            for item in resp.json().get("results", []):
                # item = [host, ip, port, protocol]
                if len(item) < 4:
                    continue
                host_field, ip, port, proto = str(item[0]), str(item[1]), str(item[2]), str(item[3])
                scheme = "https" if proto == "https" or port in ("443", "8443") else "http"
                # prefer hostname when available (not a raw IP), fall back to IP
                address = host_field if host_field and not _IP_RE.match(host_field) else ip
                urls.append(f"{scheme}://{address}:{port}")
            return SourceResult(urls=list(dict.fromkeys(urls)))
        except Exception as e:
            return SourceResult(urls=[], error=str(e))
