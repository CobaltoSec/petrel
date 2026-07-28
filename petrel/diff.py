"""Diff utilities for Petrel — classify why servers disappeared between runs."""
from __future__ import annotations

import asyncio
from typing import Any


async def classify_disappearance(record: Any, timeout: float = 5.0) -> str:
    """
    Probe a disappeared server to classify why it vanished.

    Returns one of:
      'auth_added'  — server is up but now requires authentication (401/403)
      'url_changed' — server responded with a redirect or unexpected 2xx/4xx
      'taken_down'  — connection refused / timeout / server error (5xx)
      'unknown'     — any other unexpected exception
    """
    import httpx

    if isinstance(record, dict):
        url = record.get("url") or record.get("endpoint")
    else:
        url = getattr(record, "url", None) or getattr(record, "endpoint", None)

    if not url:
        return "unknown"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            probe_url = url.rstrip("/") + "/tools/list"
            resp = await client.post(
                probe_url,
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            )

            if resp.status_code in (401, 403):
                return "auth_added"
            elif resp.status_code in (301, 302, 307, 308):
                return "url_changed"
            elif resp.status_code < 500:
                return "url_changed"  # server is up but different
            else:
                return "taken_down"

    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        return "taken_down"
    except Exception:
        return "unknown"


async def classify_disappearances_batch(
    records: list[Any],
    timeout: float = 5.0,
    concurrency: int = 10,
) -> dict[str, list[Any]]:
    """
    Probe a list of disappeared records concurrently and group them by reason.

    Args:
        records: List of MCPServerRecord objects or raw dicts with a 'url' key.
        timeout: Per-request timeout in seconds.
        concurrency: Max simultaneous probes.

    Returns:
        Dict with keys 'auth_added', 'taken_down', 'url_changed', 'unknown',
        each mapping to the list of records classified under that reason.
    """
    result: dict[str, list[Any]] = {
        "auth_added": [],
        "taken_down": [],
        "url_changed": [],
        "unknown": [],
    }

    if not records:
        return result

    sem = asyncio.Semaphore(concurrency)

    async def _probe_one(rec: Any) -> tuple[Any, str]:
        async with sem:
            reason = await classify_disappearance(rec, timeout=timeout)
        return rec, reason

    tasks = [_probe_one(r) for r in records]
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)

    for item in outcomes:
        if isinstance(item, Exception):
            # Should not happen since classify_disappearance catches all exceptions,
            # but guard defensively.
            continue
        rec, reason = item
        result.setdefault(reason, []).append(rec)

    return result
