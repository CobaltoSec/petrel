# Changelog

## [Unreleased]

## [0.2.0] — 2026-07-15

### Added
- `petrel feed-corvus <results.jsonl>` — convierte resultados Petrel → YAML targets para `corvus batch`. Filtra SSE-legacy (corvus no lo soporta), agrega `/mcp` path explícito, taggea HIGH+ con `petrel-high/no-auth`
- `petrel discover`: Censys opcional via `CENSYS_API_ID` + `CENSYS_API_SECRET` (250 queries/mes free)
- `petrel discover`: 4 queries HuggingFace con paginación (500/página) — sube de 100 a 564+ spaces
- `petrel discover`: 4 keywords crt.sh en secuencia (sin wildcard, sin doble-encoding)
- 12 nuevos tests para crtsh/hf/censys (33 total)

### Fixed
- `_probe_sse()`: SSE servers nunca tenían tools enumerados — ahora llama `_get_tools()` tras inicializar (+60% servers confirmados: 45→72)
- `RiskTier` display en tabla CLI: `tier.value` en lugar de `str(tier)` (evitaba `RiskTier.LOW` truncado)

## [0.1.0] — 2026-07-15

### Added
- `petrel probe <url>` — fingerprint a single MCP server
- `petrel discover` — passive discovery via crt.sh + HuggingFace Spaces
- `petrel scan <targets.txt>` — batch fingerprint from file
- Streamable HTTP protocol detection (2024-11-05)
- SSE legacy protocol detection
- Auth state detection (none/bearer/oauth/required)
- Risk scoring: tool-level (CRITICAL/HIGH/MEDIUM/LOW) + server-level
- Cloudflare detection
- JSONL output for pipeline with Corvus
