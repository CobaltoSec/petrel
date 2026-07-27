"""CobaltoHQ integration — emit petrel.server.critical/high events for high-risk MCP servers."""
from __future__ import annotations
from collections import Counter
from ..models import MCPServerRecord, RiskTier


def emit_scan_completed(
    records: list[MCPServerRecord],
    command: str = "scan",
    targets_count: int | None = None,
    output_file: str | None = None,
) -> bool:
    """Emit petrel.scan.completed summary event with aggregated stats.

    Requires cobaltosec-hub to be installed. Silently no-ops if not available.
    """
    try:
        from cobalt_hub_client import emit  # type: ignore[import]
    except ImportError:
        return False
    try:
        tier_counts = Counter(r.risk_tier.value for r in records)
        payload: dict = {
            "command": command,
            "confirmed_count": len(records),
            "critical_count": tier_counts.get("CRITICAL", 0),
            "high_count": tier_counts.get("HIGH", 0),
            "medium_count": tier_counts.get("MEDIUM", 0),
        }
        if targets_count is not None:
            payload["targets_count"] = targets_count
        if output_file:
            payload["output_file"] = output_file
        return emit("petrel.scan.completed", payload, "petrel")
    except Exception:
        return False


def emit_critical_servers(records: list[MCPServerRecord]) -> int:
    """Emit petrel.server.{critical,high} events for CRITICAL and HIGH servers.

    Requires cobaltosec-hub to be installed. Silently no-ops if not available.
    Returns the number of events emitted.
    """
    try:
        from cobalt_hub_client import emit  # type: ignore[import]
    except ImportError:
        return 0

    emitted = 0
    for rec in records:
        if rec.risk_tier not in (RiskTier.CRITICAL, RiskTier.HIGH):
            continue
        try:
            emit(
                f"petrel.server.{rec.risk_tier.value.lower()}",
                {
                    "url": rec.url,
                    "protocol": rec.protocol.value,
                    "auth": rec.auth_state.value,
                    "tools": [t.name for t in rec.tools if t.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH)],
                    "risk_reasons": rec.risk_reasons,
                    "discovered_via": rec.discovered_via,
                },
                "petrel",
            )
            emitted += 1
        except Exception:
            pass
    return emitted
