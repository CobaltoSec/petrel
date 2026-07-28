"""Tests for petrel.diff — classify_disappearance and classify_disappearances_batch."""
from __future__ import annotations

import pytest
import httpx
from pytest_httpx import HTTPXMock

from petrel.diff import classify_disappearance, classify_disappearances_batch


# ---------------------------------------------------------------------------
# classify_disappearance
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_classify_auth_added(httpx_mock: HTTPXMock):
    """401 response → 'auth_added'."""
    httpx_mock.add_response(
        method="POST",
        url="https://server.example.com/tools/list",
        status_code=401,
    )
    record = {"url": "https://server.example.com"}
    result = await classify_disappearance(record)
    assert result == "auth_added"


@pytest.mark.asyncio
async def test_classify_taken_down(httpx_mock: HTTPXMock):
    """ConnectError → 'taken_down'."""
    httpx_mock.add_exception(
        httpx.ConnectError("connection refused"),
        method="POST",
        url="https://gone.example.com/tools/list",
    )
    record = {"url": "https://gone.example.com"}
    result = await classify_disappearance(record)
    assert result == "taken_down"


@pytest.mark.asyncio
async def test_classify_url_changed(httpx_mock: HTTPXMock):
    """301 redirect → 'url_changed'."""
    httpx_mock.add_response(
        method="POST",
        url="https://moved.example.com/tools/list",
        status_code=301,
        headers={"Location": "https://new.example.com/tools/list"},
    )
    record = {"url": "https://moved.example.com"}
    result = await classify_disappearance(record)
    assert result == "url_changed"


# ---------------------------------------------------------------------------
# classify_disappearances_batch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_classify_batch_groups_correctly(httpx_mock: HTTPXMock):
    """Batch function groups records into the correct buckets."""
    httpx_mock.add_response(
        method="POST",
        url="https://auth.example.com/tools/list",
        status_code=403,
    )
    httpx_mock.add_exception(
        httpx.TimeoutException("timed out"),
        method="POST",
        url="https://down.example.com/tools/list",
    )

    records = [
        {"url": "https://auth.example.com"},
        {"url": "https://down.example.com"},
    ]
    groups = await classify_disappearances_batch(records)

    assert len(groups["auth_added"]) == 1
    assert len(groups["taken_down"]) == 1
    assert len(groups["url_changed"]) == 0
    assert len(groups["unknown"]) == 0


@pytest.mark.asyncio
async def test_classify_disappearance_no_url():
    """Record with no URL → 'unknown'."""
    result = await classify_disappearance({})
    assert result == "unknown"


@pytest.mark.asyncio
async def test_classify_taken_down_5xx(httpx_mock: HTTPXMock):
    """5xx server error → 'taken_down'."""
    httpx_mock.add_response(
        method="POST",
        url="https://error.example.com/tools/list",
        status_code=503,
    )
    record = {"url": "https://error.example.com"}
    result = await classify_disappearance(record)
    assert result == "taken_down"
