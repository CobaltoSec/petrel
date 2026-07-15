"""Platform-specific discovery (cloud platforms where MCP servers get deployed)."""
from __future__ import annotations

PLATFORM_SUFFIXES: dict[str, str] = {
    "hf": "hf.space",
    "vercel": "vercel.app",
    "railway": "railway.app",
    "render": "onrender.com",
    "fly": "fly.dev",
    "replit": "replit.dev",
    "modal": "modal.run",
    "huggingface": "hf.space",
}

ALL_PLATFORMS = list(PLATFORM_SUFFIXES.keys())
