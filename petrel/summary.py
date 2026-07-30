"""Post-run funnel markdown summary for Petrel discovery runs."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AuthState, MCPServerRecord, RiskTier


def generate_run_summary(
    run_id: int,
    results: list[MCPServerRecord],
    decay_stats: dict[str, Any],
    candidate_count: int = 0,
    output_dir: Path | None = None,
) -> Path:
    """Generate a markdown funnel summary for a discovery run.

    Args:
        run_id: The run ID from the SQLite store.
        results: Confirmed MCP server records (already scored).
        decay_stats: Dict with 'new' and 'decayed' keys from update_server_history.
        candidate_count: Total candidates before fingerprinting (0 falls back to confirmed).
        output_dir: Where to save. Defaults to ~/.petrel/summaries/.

    Returns:
        Path to the saved markdown file.
    """
    confirmed = len(results)
    critical = sum(1 for r in results if r.risk_tier == RiskTier.CRITICAL)
    no_auth = sum(1 for r in results if r.auth_state == AuthState.NONE)
    new_this_run = decay_stats.get("new", 0)
    decayed = decay_stats.get("decayed", 0)
    candidates = candidate_count if candidate_count > 0 else confirmed

    def _pct(n: int, total: int) -> str:
        if total == 0:
            return "-"
        return f"{n / total * 100:.1f}%"

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [
        f"# Petrel Run #{run_id} — {today}",
        "",
        "## Funnel",
        "",
        "| Metric | Count | % of Candidates |",
        "| --- | ---: | ---: |",
        f"| Candidatos totales | {candidates} | 100% |",
        f"| Confirmados MCP | {confirmed} | {_pct(confirmed, candidates)} |",
        f"| CRITICAL | {critical} | {_pct(critical, candidates)} |",
        f"| Sin autenticacion | {no_auth} | {_pct(no_auth, candidates)} |",
        f"| Nuevos esta run | {new_this_run} | - |",
        f"| Decaidos | {decayed} | - |",
        "",
    ]

    content = "\n".join(lines)

    summaries_dir = Path(output_dir) if output_dir is not None else Path.home() / ".petrel" / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)

    out_path = summaries_dir / f"run-{run_id}-{today}.md"
    out_path.write_text(content, encoding="utf-8")
    return out_path
