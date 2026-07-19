"""Self-contained dark-theme HTML report for Petrel scan results."""
from __future__ import annotations
from collections import Counter
from pathlib import Path
from ..models import MCPServerRecord, RiskTier

_TIER_COLOR = {
    RiskTier.CRITICAL: "#ff4444",
    RiskTier.HIGH: "#ff8c00",
    RiskTier.MEDIUM: "#ffd700",
    RiskTier.LOW: "#90ee90",
    RiskTier.INFO: "#888888",
}


def records_to_html(records: list[MCPServerRecord], title: str = "Petrel Scan Report") -> str:
    counts = Counter(r.risk_tier for r in records)
    total = len(records)

    # Build summary bars
    summary_rows = ""
    for tier in RiskTier:
        n = counts.get(tier, 0)
        if n == 0:
            continue
        color = _TIER_COLOR[tier]
        pct = round(n / total * 100) if total else 0
        summary_rows += f"""
        <tr>
          <td style="color:{color};font-weight:bold">{tier.value}</td>
          <td>{n}</td>
          <td><div style="background:{color};width:{pct}%;height:12px;border-radius:3px;min-width:4px"></div></td>
        </tr>"""

    # Build server cards
    cards = ""
    for rec in sorted(records, key=lambda r: list(RiskTier).index(r.risk_tier)):
        color = _TIER_COLOR[rec.risk_tier]
        tools_html = "".join(
            f'<span style="background:#333;padding:2px 6px;border-radius:3px;margin:2px;display:inline-block;color:{_TIER_COLOR.get(t.risk_tier,"#aaa")}">{t.name}</span>'
            for t in rec.tools[:20]
        )
        reasons_html = "".join(f"<li>{r}</li>" for r in rec.risk_reasons)
        cards += f"""
        <div style="background:#1e1e1e;border-left:4px solid {color};padding:14px;margin:10px 0;border-radius:4px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="color:{color};font-weight:bold">{rec.risk_tier.value}</span>
            <span style="color:#888;font-size:12px">{rec.protocol.value} · {rec.auth_state.value} · {rec.platform.value}</span>
          </div>
          <div style="font-size:14px;margin:6px 0"><a href="{rec.url}" style="color:#4af">{rec.url}</a></div>
          {f'<div style="color:#aaa;font-size:12px">{rec.server_name} {rec.server_version or ""}</div>' if rec.server_name else ""}
          {f'<ul style="color:#f88;font-size:12px;margin:6px 0">{reasons_html}</ul>' if reasons_html else ""}
          <div style="margin-top:8px">{tools_html}</div>
          <div style="color:#888;font-size:11px;margin-top:6px">via: {rec.discovered_via}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body{{background:#121212;color:#e0e0e0;font-family:monospace;padding:20px;max-width:960px;margin:0 auto}}
  h1{{color:#4af}}
  table{{border-collapse:collapse;width:100%;margin:16px 0}}
  td{{padding:6px 12px;border-bottom:1px solid #333}}
  a{{color:#4af}}
</style>
</head>
<body>
<h1>Petrel: {title}</h1>
<p style="color:#888">{total} MCP servers confirmed</p>
<table>{summary_rows}</table>
<h2 style="color:#aaa">Servers</h2>
{cards}
</body>
</html>"""


def write_html(records: list[MCPServerRecord], path: Path, title: str = "Petrel Scan Report") -> None:
    path.write_text(records_to_html(records, title), encoding="utf-8")
