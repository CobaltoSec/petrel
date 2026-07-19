"""CobaltoHQ integration — emit petrel.server.critical events for CRITICAL MCP servers."""
from __future__ import annotations
from ..models import MCPServerRecord, RiskTier


def emit_critical_servers(records: list[MCPServerRecord]) -> int:
    """Emit petrel.server.critical events for each CRITICAL server found.

    Requires cobaltosec-hub to be installed. Silently no-ops if not available.
    Returns the number of events emitted.
    """
    try:
        from cobaltohq.client import emit  # type: ignore[import]
    except ImportError:
        return 0

    emitted = 0
    for rec in records:
        if rec.risk_tier != RiskTier.CRITICAL:
            continue
        try:
            emit(
                "petrel.server.critical",
                {
                    "url": rec.url,
                    "protocol": rec.protocol.value,
                    "auth": rec.auth_state.value,
                    "tools": [t.name for t in rec.tools if t.risk_tier == RiskTier.CRITICAL],
                    "risk_reasons": rec.risk_reasons,
                    "discovered_via": rec.discovered_via,
                },
            )
            emitted += 1
        except Exception:
            pass
    return emitted
