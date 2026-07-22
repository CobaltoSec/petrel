"""Core data models for Petrel."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceResult(list):
    """Result from a discovery source function.

    Extends list for backwards compatibility — existing code that does
    ``"url" in result`` or ``result == []`` continues to work unchanged.
    New code can inspect ``.urls``, ``.warnings``, and ``.error``.
    """

    def __init__(
        self,
        urls: list[str],
        warnings: list[str] | None = None,
        error: str | None = None,
    ) -> None:
        super().__init__(urls)
        self.urls: list[str] = urls
        self.warnings: list[str] = warnings if warnings is not None else []
        self.error: str | None = error


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


def worst_tier(*tiers: RiskTier) -> RiskTier:
    return min(tiers, key=lambda t: _TIER_ORDER.index(t))


class Platform(str, Enum):
    HUGGINGFACE = "huggingface"
    VERCEL = "vercel"
    RAILWAY = "railway"
    FLY = "fly.io"
    AWS_LAMBDA = "aws-lambda"
    GCP = "gcp"
    AZURE = "azure"
    CLOUDFLARE_WORKERS = "cloudflare-workers"
    RENDER = "render"
    UNKNOWN = "unknown"


class MCPResource(BaseModel):
    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = Field(default=None, alias="mimeType")
    model_config = {"populate_by_name": True}


class MCPPromptArgument(BaseModel):
    name: str
    description: str | None = None
    required: bool = False


class MCPPrompt(BaseModel):
    name: str
    description: str | None = None
    arguments: list[MCPPromptArgument] = []


class MCPTool(BaseModel):
    name: str
    description: str | None = None
    input_schema: dict[str, Any] | None = Field(default=None, alias="inputSchema")
    annotations: dict[str, Any] | None = None
    risk_tier: RiskTier = RiskTier.INFO
    schema_risk_params: list[str] = []  # dangerous inputSchema param names found by scorer

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
    priority_score: int = 0
    risk_reasons: list[str] = []
    behind_cloudflare: bool = False
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # M1 — probe detail
    endpoint_path: str | None = None
    server_capabilities: dict[str, Any] = Field(default_factory=dict)
    server_instructions: str | None = None
    final_url: str | None = None
    redirect_count: int = 0

    # M2 — MCP primitives
    resources: list[MCPResource] = []
    prompts: list[MCPPrompt] = []

    # M3 — hosting platform
    platform: Platform = Platform.UNKNOWN

    @property
    def is_confirmed_mcp(self) -> bool:
        return self.protocol != Protocol.UNKNOWN

    @property
    def has_auth(self) -> bool:
        return self.auth_state not in (AuthState.NONE, AuthState.UNKNOWN)
