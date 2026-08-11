"""Diff utilities for Petrel — classify why servers disappeared between runs."""
from __future__ import annotations

import asyncio
from typing import Any


async def classify_disappearance(record: Any, timeout: float = 5.0) -> str:
    """
    Re-probe a disappeared server and classify why it vanished.

    The function first attempts a full MCP fingerprint via probe_url.  If the
    server responds and is confirmed MCP it was only temporarily offline
    ('intermittent').  Otherwise a raw HTTP probe determines the reason.

    Returns one of:
      'intermittent' — server is back up as a valid MCP server (was temporarily offline)
      'auth_added'   — server is up but now requires authentication (401/403)
      'url_changed'  — server responded with a redirect or unexpected 2xx/4xx
      'taken_down'   — connection refused / timeout / server error (5xx)
      'unknown'      — any other unexpected exception
    """
    import httpx

    if isinstance(record, dict):
        url = record.get("url") or record.get("endpoint")
    else:
        url = getattr(record, "url", None) or getattr(record, "endpoint", None)

    if not url:
        return "unknown"

    # Step 1 — re-probe with the full MCP fingerprinter.
    # A confirmed MCP response means the server was only transiently offline.
    try:
        from .fingerprint.probe import probe_url as _probe_url

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=3.0, read=timeout, write=3.0, pool=3.0),
            follow_redirects=True,
        ) as recheck_client:
            mcp_result = await _probe_url(url, recheck_client)

        if mcp_result is not None and mcp_result.is_confirmed_mcp:
            return "intermittent"
    except Exception:
        pass  # network failure — fall through to raw HTTP classification

    # Step 2 — raw HTTP classification to determine why the server is gone.
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            check_endpoint = url.rstrip("/") + "/tools/list"
            resp = await client.post(
                check_endpoint,
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
    current_servers: list[Any] | None = None,
) -> dict[str, list[Any]]:
    """
    Probe a list of disappeared records concurrently and group them by reason.

    Args:
        records: List of MCPServerRecord objects or raw dicts with a 'url' key.
        timeout: Per-request timeout in seconds.
        concurrency: Max simultaneous probes.
        current_servers: Servers confirmed in the current run.  Used to detect
            URL migrations: if a disappeared server's tool_name_hash matches a
            current server at a different URL, it is classified as 'url_changed'
            without re-probing.

    Returns:
        Dict with keys 'auth_added', 'taken_down', 'url_changed', 'unknown',
        each mapping to the list of records classified under that reason.
    """
    result: dict[str, list[Any]] = {
        "intermittent": [],
        "auth_added": [],
        "taken_down": [],
        "url_changed": [],
        "unknown": [],
    }

    if not records:
        return result

    # Build a hash→url index from the current run so we can detect migrations
    # without re-probing: same tool_name_hash at a different URL = server moved.
    current_hashes: dict[str, str] = {}
    for srv in (current_servers or []):
        if isinstance(srv, dict):
            h = srv.get("tool_name_hash")
            u = srv.get("url") or srv.get("endpoint")
        else:
            h = getattr(srv, "tool_name_hash", None)
            u = getattr(srv, "url", None) or getattr(srv, "endpoint", None)
        if h and u:
            current_hashes[h] = u

    # Partition: records we can classify via hash-match vs those needing a probe.
    needs_probe: list[Any] = []
    for rec in records:
        if isinstance(rec, dict):
            rec_hash = rec.get("tool_name_hash")
            rec_url = rec.get("url") or rec.get("endpoint")
        else:
            rec_hash = getattr(rec, "tool_name_hash", None)
            rec_url = getattr(rec, "url", None) or getattr(rec, "endpoint", None)

        if rec_hash and rec_hash in current_hashes and current_hashes[rec_hash] != rec_url:
            result["url_changed"].append(rec)
        else:
            needs_probe.append(rec)

    sem = asyncio.Semaphore(concurrency)

    async def _probe_one(rec: Any) -> tuple[Any, str]:
        async with sem:
            reason = await classify_disappearance(rec, timeout=timeout)
        return rec, reason

    tasks = [_probe_one(r) for r in needs_probe]
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)

    for item in outcomes:
        if isinstance(item, Exception):
            # Should not happen since classify_disappearance catches all exceptions,
            # but guard defensively.
            continue
        rec, reason = item
        result.setdefault(reason, []).append(rec)

    # Annotate CRITICAL servers (priority_score >= 80) confirmed as taken_down
    # with verified_gone=True so callers can surface them prominently.
    for rec in result["taken_down"]:
        priority = (
            rec.get("priority_score", 0)
            if isinstance(rec, dict)
            else getattr(rec, "priority_score", 0)
        )
        if priority >= 80:
            if isinstance(rec, dict):
                rec["verified_gone"] = True
            else:
                try:
                    rec.verified_gone = True  # type: ignore[attr-defined]
                except (AttributeError, TypeError):
                    pass

    return result
