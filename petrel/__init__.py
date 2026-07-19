"""Petrel — MCP Internet Scanner & Fingerprinter."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__: str = _pkg_version("cobaltosec-petrel")
except PackageNotFoundError:
    __version__ = "0.4.0"

from .models import AuthState, MCPServerRecord, MCPTool, Protocol, RiskTier

__all__ = [
    "__version__",
    "AuthState",
    "MCPServerRecord",
    "MCPTool",
    "Protocol",
    "RiskTier",
]
