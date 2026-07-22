"""CSV output formatter for Petrel."""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Sequence

from ..models import MCPServerRecord

_FIELDS = [
    "url",
    "risk_tier",
    "auth_state",
    "protocol",
    "tool_count",
    "platform",
    "priority_score",
    "behind_cloudflare",
]


def write_csv(records: Sequence[MCPServerRecord], path: Path) -> None:
    """Write records as CSV."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_FIELDS)
    w.writeheader()
    for r in records:
        w.writerow({
            "url": r.url,
            "risk_tier": r.risk_tier.value,
            "auth_state": r.auth_state.value,
            "protocol": r.protocol.value,
            "tool_count": len(r.tools),
            "platform": r.platform.value if r.platform else "",
            "priority_score": r.priority_score,
            "behind_cloudflare": r.behind_cloudflare,
        })
    path.write_text(buf.getvalue(), encoding="utf-8")
