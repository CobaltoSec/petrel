# Changelog

## [Unreleased]

## [0.3.0] — 2026-07-17

### Added
- `petrel discover`: GitHub passive search — 4 queries a la GitHub Search API (topic:mcp-server, in:name, in:readme), extrae `homepage` de repos filtrando source/docs links. Rate-limit aware: 6s entre queries sin token, 2s con `GITHUB_TOKEN`
- `petrel discover`: npm registry passive — 4 queries concurrentes al registry público, extrae `links.homepage` de paquetes. Sin API key requerida
- `petrel discover --no-github` / `--no-npm` para saltar fuentes individualmente
- Cobertura real: 850 candidatos (vs 562 anterior, +51%)

### Fixed
- crt.sh: agrega `User-Agent: petrel/0.3.0 (security research)` para evitar bloqueos silenciosos
- crt.sh: retry hasta 2 veces en `ReadTimeout`/`NetworkError` con backoff, y en 429 espera 5s
- Skip list: agrega `github.io`, `npmjs.org`, `discord.com` en ambos módulos de discovery
- 13 nuevos tests (33→46 total)

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
