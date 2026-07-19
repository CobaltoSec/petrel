"""SARIF 2.1.0 output for Petrel scan results."""
from __future__ import annotations
import json
from pathlib import Path
from ..models import MCPServerRecord, RiskTier

_LEVEL_MAP = {
    RiskTier.CRITICAL: "error",
    RiskTier.HIGH: "error",
    RiskTier.MEDIUM: "warning",
    RiskTier.LOW: "note",
    RiskTier.INFO: "none",
}
_RANK_MAP = {
    RiskTier.CRITICAL: 100.0,
    RiskTier.HIGH: 75.0,
    RiskTier.MEDIUM: 50.0,
    RiskTier.LOW: 25.0,
    RiskTier.INFO: 0.0,
}


def records_to_sarif(records: list[MCPServerRecord]) -> dict:
    """Convert Petrel scan results to SARIF 2.1.0 format."""
    rules = []
    rule_ids: set[str] = set()

    results = []
    for rec in records:
        rule_id = f"PETREL-{rec.risk_tier.value}"
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f"MCP{rec.risk_tier.value.title()}Server",
                "shortDescription": {"text": f"{rec.risk_tier.value} risk MCP server"},
                "defaultConfiguration": {"level": _LEVEL_MAP[rec.risk_tier]},
                "properties": {"tags": ["mcp", "security"]},
            })

        message_parts = [f"MCP server at {rec.url} — risk: {rec.risk_tier.value}"]
        if rec.risk_reasons:
            message_parts.append("Findings: " + "; ".join(rec.risk_reasons))
        if rec.tools:
            tool_names = [t.name for t in rec.tools[:10]]
            message_parts.append(f"Tools ({len(rec.tools)}): {', '.join(tool_names)}")

        results.append({
            "ruleId": rule_id,
            "level": _LEVEL_MAP[rec.risk_tier],
            "rank": _RANK_MAP[rec.risk_tier],
            "message": {"text": " | ".join(message_parts)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rec.url, "uriBaseId": "%SRCROOT%"},
                }
            }],
            "properties": {
                "protocol": rec.protocol.value,
                "auth": rec.auth_state.value,
                "tool_count": len(rec.tools),
                "discovered_via": rec.discovered_via,
                "platform": rec.platform.value,
            },
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "petrel",
                    "version": "0.4.0",
                    "informationUri": "https://github.com/CobaltoSec/petrel",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def write_sarif(records: list[MCPServerRecord], path: Path) -> None:
    sarif = records_to_sarif(records)
    path.write_text(json.dumps(sarif, indent=2, default=str))
