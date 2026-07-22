"""Markdown table output formatter for Petrel."""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..models import MCPServerRecord


def write_markdown(records: Sequence[MCPServerRecord], path: Path) -> None:
    """Write records as a Markdown table."""
    lines = [
        "| URL | Risk | Auth | Protocol | Tools | Platform |",
        "|-----|------|------|----------|-------|----------|",
    ]
    for r in records:
        lines.append(
            f"| {r.url} | {r.risk_tier.value} | {r.auth_state.value} | "
            f"{r.protocol.value} | {len(r.tools)} | {r.platform.value if r.platform else ''} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
