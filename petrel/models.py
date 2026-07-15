"""Core data models for Petrel."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Protocol(str, Enum):
    STREAMABLE_HTTP = "streamable-http"
    SSE_LEGACY = "sse-legacy"
    UNKNOWN = "unknown"


class AuthState(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    OAUTH = "oauth"
    API_KEY = "api-key"
    REQUIRED = "required"
    UNKNOWN = "unknown"


class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_TIER_ORDER = [RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM, RiskTier.LOW, RiskTier.INFO]


def worst_tier(a: RiskTier, b: RiskTier) -> RiskTier:
    return a if _TIER_ORDER.index(a) <= _TIER_ORDER.index(b) else b


class MCPTool(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] | None = Field(default=None, alias="inputSchema")
    risk_tier: RiskTier = RiskTier.INFO

    model_config = {"populate_by_name": True}


class MCPServerRecord(BaseModel):
    url: str
    discovered_via: str = "probe"
    protocol: Protocol = Protocol.UNKNOWN
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None
    tools: list[MCPTool] = []
    auth_state: AuthState = AuthState.UNKNOWN
    risk_tier: RiskTier = RiskTier.INFO
    risk_reasons: list[str] = []
    behind_cloudflare: bool = False
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_confirmed_mcp(self) -> bool:
        return self.protocol != Protocol.UNKNOWN

    @property
    def has_auth(self) -> bool:
        return self.auth_state not in (AuthState.NONE, AuthState.UNKNOWN)
