"""CobaltoHQ integration — emit petrel.server.critical/high events for high-risk MCP servers."""
from __future__ import annotations
from ..models import MCPServerRecord, RiskTier


def emit_critical_servers(records: list[MCPServerRecord]) -> int:
    """Emit petrel.server.{critical,high} events for CRITICAL and HIGH servers.

    Requires cobaltosec-hub to be installed. Silently no-ops if not available.
    Returns the number of events emitted.
    """
    try:
        from cobaltohq.client import emit  # type: ignore[import]
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
            )
            emitted += 1
        except Exception:
            pass
    return emitted
