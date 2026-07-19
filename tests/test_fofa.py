"""Tests for FOFA discovery."""
from __future__ import annotations
import base64
import re
import pytest
from pytest_httpx import HTTPXMock
from petrel.discovery.fofa import fofa_search

_FOFA_URL = "https://fofa.info/api/v1/search/all"
_FOFA_RE = re.compile(r"https://fofa\.info/api/v1/search/all")


@pytest.mark.asyncio
async def test_fofa_no_credentials_returns_empty(monkeypatch):
    monkeypatch.delenv("FOFA_EMAIL", raising=False)
    monkeypatch.delenv("FOFA_KEY", raising=False)
    result = await fofa_search()
    assert result == []


@pytest.mark.asyncio
async def test_fofa_builds_https_for_port_443(httpx_mock: HTTPXMock, monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "test@example.com")
    monkeypatch.setenv("FOFA_KEY", "testkey")
    httpx_mock.add_response(
        url=_FOFA_RE,
        json={"results": [["1.2.3.4", "443", "https"]]},
    )
    urls = await fofa_search()
    assert "https://1.2.3.4:443" in urls


@pytest.mark.asyncio
async def test_fofa_builds_http_for_other_ports(httpx_mock: HTTPXMock, monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "test@example.com")
    monkeypatch.setenv("FOFA_KEY", "testkey")
    httpx_mock.add_response(
        url=_FOFA_RE,
        json={"results": [["5.6.7.8", "8080", "http"]]},
    )
    urls = await fofa_search()
    assert "http://5.6.7.8:8080" in urls


@pytest.mark.asyncio
async def test_fofa_api_error_returns_empty(httpx_mock: HTTPXMock, monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "e")
    monkeypatch.setenv("FOFA_KEY", "k")
    httpx_mock.add_response(url=_FOFA_RE, status_code=403)
    result = await fofa_search()
    assert result == []


@pytest.mark.asyncio
async def test_fofa_encodes_query_as_base64(httpx_mock: HTTPXMock, monkeypatch):
    monkeypatch.setenv("FOFA_EMAIL", "e")
    monkeypatch.setenv("FOFA_KEY", "k")
    httpx_mock.add_response(url=_FOFA_RE, json={"results": []})
    await fofa_search()
    reqs = httpx_mock.get_requests()
    assert len(reqs) == 1
    qb64 = reqs[0].url.params.get("qbase64", "")
    decoded = base64.b64decode(qb64).decode()
    assert "serverInfo" in decoded
    assert "protocolVersion" in decoded
