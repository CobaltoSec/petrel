"""Passive discovery: crt.sh and HuggingFace Spaces (no API key required)."""
from __future__ import annotations

import httpx


async def crtsh_search(keyword: str = "mcp") -> list[str]:
    """Search certificate transparency logs for MCP-related domains."""
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%25{keyword}%25", "output": "json"},
            )
            if resp.status_code != 200:
                return []

            domains: set[str] = set()
            for entry in resp.json():
                name_value = entry.get("name_value", "")
                for domain in name_value.split("\n"):
                    domain = domain.strip().lstrip("*.")
                    if domain and keyword.lower() in domain.lower() and "." in domain:
                        domains.add(domain)

            return sorted(domains)
        except Exception:
            return []


async def hf_spaces_search(query: str = "mcp-server", limit: int = 100) -> list[str]:
    """Find MCP server spaces on HuggingFace (no API key needed)."""
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            resp = await client.get(
                "https://huggingface.co/api/spaces",
                params={"search": query, "limit": limit, "sort": "likes"},
            )
            if resp.status_code != 200:
                return []

            urls: list[str] = []
            for space in resp.json():
                space_id = space.get("id", "")
                if not space_id or "/" not in space_id:
                    continue
                owner, name = space_id.split("/", 1)
                # HF Spaces URL format: https://owner-name.hf.space
                slug = f"{owner}-{name}".lower().replace("_", "-")
                urls.append(f"https://{slug}.hf.space")

            return urls
        except Exception:
            return []
