# Changelog

## [Unreleased]

## [PETREL-CFP-LATAM] — 2026-07-22

### Research
- Geolocate LATAM: DNS resolve + ip-api.com/batch sobre `results-v07.jsonl` — sin servers LATAM genuinos (CDN false positives: Cloudflare Toronto → CA para 135/276 hosts). Script en `scripts/latam_stats.py`
- CFP: pivote de ángulo LATAM a números globales Run 3 (más sólidos y verificables)

### CFP Ekoparty 2026 (deadline 14 agosto)
- Abstract actualizado con Run 3: 3,948 candidatos → 464 confirmados, 41 CRITICAL, 23% sin auth, 50+ GHSAs — `docs/cfp-ekoparty-2026.md`
- Slide deck 15 slides generado (dark oceanic / teal accent) → `Downloads/petrel-ekoparty-2026.html`
- PDF 15 páginas vía Playwright screenshot-por-slide → `Downloads/petrel-slides-2026.pdf`
- Submitted a Sessionize — 3/3 slots usados (Corvus + Condor + Petrel)

## [PETREL-V08] — 2026-07-22

### Added
- Discovery: GitHub README parsing — cuando un repo no tiene `homepage`, hace GET a GitHub Contents API para extraer URLs de deployment del README (railway.app, fly.dev, vercel.app, hf.space, onrender.com). Máx 1 URL por repo (DISC-006)
- Discovery: Shodan source — query `http.html:"2024-11-05"`; requiere `SHODAN_API_KEY`. Hasta 1,000 hosts/run. Highest-signal internet scanner para MCP (DISC-007)
- Discovery: MCP registries — glama.ai (`/api/mcp/v1/servers`) + pulsemcp.com (`/v0beta/servers`), paginados, sin API key. Listas curadas de MCP servers (DISC-013)
- CLI: `discover` — flags `--no-shodan` / `--no-registries`. Shodan solo activo con `SHODAN_API_KEY` presente (DISC-007/013)
- CLI: `petrel report <file.jsonl>` — regenera HTML/SARIF desde JSONL existente sin re-probe (F-05)
- Fingerprint: data-plane auth check — si `tools/list` responde 401/403 pero `initialize` OK, escala `auth_state` a REQUIRED (FP-005)
- Fingerprint: retry en 503 (cold start Railway/Fly free tier) — 1 reintento con sleep 3s en `_probe_streamable`. Solo 503 (PERF-05)
- Scoring: nested inputSchema recursivo (depth ≤ 3) — detecta params peligrosos anidados en `type: object` (FP-010)
- Scoring: `server_instructions` scoring — CRITICAL para injection patterns, HIGH para credential patterns. `_score_server_instructions()` (SR-07)
- Scoring: `priority_score: int` 0-100 en `MCPServerRecord`. Base: CRITICAL=80, HIGH=60, MEDIUM=40, LOW=20. Bonuses: no-auth +15, exec tools +5, public platform +3. `feed-corvus` ordena por `(tier, -priority_score)` (SR-08)

## [0.7.0] — 2026-07-22

_(PyPI publish pendiente — token requerido)_

## [PETREL-RUN3] — 2026-07-21

### Fixed
- Discovery: Smithery.ai — migrado de `smithery.ai/api/v1/servers` (404) a `api.smithery.ai/servers`. Nueva paginación `pagination.currentPage/totalPages`. Extrae `homepage` del listado en lugar de `connections[].deploymentUrl` (todos apuntan a `*.run.tools`, inaccesibles sin auth Smithery). 118 candidatos → 45 confirmados (38% conversión, mejor ratio de todas las fuentes)
- Tests: smithery tests reescritos para nueva API — 12 tests, todos passing (212/212 total)

### Run 3 (2026-07-21)
- 3,948 candidatos (PyPI 2001 + GitHub 938 + HuggingFace 565 + Smithery 118 + npm 469 + crt.sh 1) → 464 confirmados (11.7%)
- 41 CRITICAL, 4 HIGH, 61 LOW, 358 INFO — 106 sin auth
- Smithery: 45 de sus 118 candidatos son MCP servers reales (38% — nuevos: theagenttimes.com, ucpg.ai, vivaldo.shop, xqb.io/mcp, emblemvault.ai)
- Outputs: `results-v07.jsonl`, `results-v07.sarif`, `results-v07.html`, `targets-v07.yaml` (450 targets HTTP para CS17)

## [0.6.0] — 2026-07-21

### Added
- Discovery: Censys cursor pagination — up to 500 results/run (was 100). Loops via `result.links.next` cursor (DISC-008)
- Discovery: npm offset pagination via `from` param — up to 1,000 results/query (was 250). 4 pages × 250 per query (DISC-009)
- Discovery: `SourceResult` namedtuple — all 7 discovery functions now surface `.urls`, `.warnings`, `.error` instead of silently returning `[]` on failure (DISC-011)
- Discovery: URL normalization pre-dedup — strips trailing slashes, lowercases host, removes default ports (DISC-002)
- Discovery: All sources now run concurrently via `asyncio.gather` (was serial, 4–8 min overhead) (PERF-02)
- Fingerprint: SSE session path extracted via regex instead of `/messages` literal — catches `/api/v1/messages`, `/connect`, custom paths (FP-007)
- Fingerprint: Tool `annotations` (`destructive`, `readOnly`, `openWorld`) captured in `MCPTool.annotations` (FP-008)
- Fingerprint: `tools/list` cursor pagination — enumerates servers with 200+ tools (up to 10 pages × N tools) (FP-009)
- CLI: `discover` / `scan` — incremental JSONL output via `on_result` callback; crash recovery via `--resume` works with partial files (PERF-01)
- CLI: Rich progress bar with ETA during fingerprinting phase (PERF-07)
- CLI: `diff` shows **Disappeared** servers (in old run but not in new) (F-03)
- CLI: `diff` shows **New Tools in Existing Servers** (tool set comparison per server) (F-04)
- 31 new tests (177 → 208, all passing)

### Fixed
- Scoring: Wide-surface CRITICAL FP — 50+ getter tools with no auth no longer scores CRITICAL. Auth escalation (HIGH→CRITICAL) now only fires when `capability_tier` is HIGH/CRITICAL from actual dangerous tools, not from structural signals (wide surface, dangerous server name) (SR-05)
- Scoring: `sampling` capability + FS_READ tools → CRITICAL. Flags autonomous exfiltration vector: LLM can read files and initiate outbound calls without human interaction (SR-06)

## [0.5.0] — 2026-07-19

### Added
- Discovery: Smithery.ai — `SMITHERY_API_KEY` env var + `Authorization: Bearer` header; sin key → warning + 0 resultados (antes: siempre 0 en silencio). Acceso a ~6,756 servers (DISC-001)
- Discovery: crt.sh keyword `mcp` — pre-filtro por sufijos de plataformas conocidas (`.hf.space`, `.vercel.app`, `.railway.app`, etc.) y tokens MCP en subdominio. Reduce ruido drásticamente (DISC-004)
- Fingerprint: JSON-RPC error responses (`"error"` en body) registrados como endpoints MCP confirmados, no descartados (FP-001)
- Fingerprint: `403 Forbidden` → `AuthState.REQUIRED` (antes solo 401). Cubre Cloudflare Access y API gateways (FP-003)
- Output: `cobaltohq.py` — emite `petrel.server.critical` y `petrel.server.high` events (antes solo CRITICAL). Event name dinámico (F-02)
- CLI: `feed-corvus` — tag `no-auth` solo cuando `auth_state == "none"` (antes hardcodeado en todo CRITICAL/HIGH). `risk_tier` en todas las entradas. Sort CRITICAL-first en `targets.yaml` (SR-02, F-01, SR-04)
- 16 nuevos tests (161 → 177, todos passing)

### Fixed
- Fingerprint: guard `"serverInfo" not in result` → `"protocolVersion" not in result`. Servers MCP que omiten `serverInfo` (válido por spec) ya no son descartados (FP-002)
- Scoring: `query` movido de `_SCHEMA_HIGH_PARAMS` a `_SCHEMA_MEDIUM_PARAMS` — `search_knowledge(query: str)` ya no escala a CRITICAL (SR-03)
- Scoring: clusters FS_READ+NETWORK y FS_READ+MESSAGING → CRITICAL (exfiltración). FS_WRITE+NETWORK → HIGH (supply-chain). Antes faltaban (SR-01)
- Discovery: Censys/FOFA query → `"2024-11-05"` (string exclusivo del protocolo MCP). Antes usaba `"serverInfo"/"protocolVersion"` genéricos (DISC-003)
- Performance: timeout split `connect=3s / read=8s` en todos los probes (antes: 8s plano). Ahorra 5s por path en hosts non-MCP (PERF-03)
- test_fofa: actualiza assert a `"2024-11-05"` tras cambio de query (DISC-003)

## [0.4.0] — 2026-07-18

### Added
- Discovery: Smithery.ai MCP registry — paginated, no auth required (`petrel/discovery/smithery.py`)
- Discovery: PyPI 2-phase — Simple index filter + per-package JSON for deployment URLs (`petrel/discovery/pypi.py`)
- Discovery: FOFA opcional vía `FOFA_EMAIL` + `FOFA_KEY` para cobertura Asian cloud (`petrel/discovery/fofa.py`)
- Discovery: GitHub pagination — 100 → 1,000 resultados/query (10 páginas × 100)
- Discovery: `discovered_via` correctamente propagado a todos los records (crtsh/huggingface/github/npm/smithery/pypi/censys/fofa)
- Fingerprint: `endpoint_path` guardado — `feed-corvus` ya no hardcodea `/mcp`
- Fingerprint: `server_capabilities` (sampling/roots) y `server_instructions` extraídos de `initialize`
- Fingerprint: `resources/list` + `prompts/list` enumerados concurrentemente con `tools/list`
- Fingerprint: Platform detection — Vercel/Railway/Fly/AWS/GCP/Azure desde response headers + URL patterns
- Fingerprint: `AuthState.API_KEY` — detecta API key expuesta en URL query params
- Scoring: 3 señales por tool: nombre + descripción + inputSchema params
- Scoring: Tool clustering — exec+network/exec+messaging → CRITICAL exfiltration combo
- Scoring: Señales de servidor: 50+ tools → HIGH, server name "computer-use" → HIGH, sampling capability → HIGH
- Scoring: Credentials en resource URI → CRITICAL; API key en URL → MEDIUM
- Output: `petrel/output/sarif.py` — SARIF 2.1.0 (`--sarif` en discover/scan)
- Output: `petrel/output/html.py` — HTML report dark theme self-contained (`--html` en discover/scan)
- Output: `petrel/output/cobaltohq.py` — emit `petrel.server.critical` al CobaltoHQ (auto si cobaltosec-hub instalado)
- CLI: `petrel stats <results.jsonl>` — distribución por risk/protocol/auth/platform/source
- CLI: `petrel diff <old.jsonl> <new.jsonl>` — servidores nuevos + escalaciones de riesgo
- CLI: `petrel feed-corvus --source <tag>` — filtrar por fuente de discovery
- CLI: `--resume <jsonl>` en discover — skipea URLs ya confirmadas
- CLI: `--since <jsonl>` en discover — deduplica candidatos contra run anterior
- Models: `Platform` enum, `MCPResource`, `MCPPrompt`, `MCPPromptArgument` models
- Models: `MCPServerRecord` — `endpoint_path`, `server_capabilities`, `server_instructions`, `final_url`, `redirect_count`, `resources`, `prompts`, `platform`
- Models: `worst_tier(*tiers)` variadic (antes solo aceptaba 2 args)
- 115 nuevos tests (46 → 161, todos passing)

### Fixed
- `petrel discover --no-probe` escribía `[]` en vez del listado de URLs al archivo de output
- `petrel feed-corvus` hardcodeaba `/mcp`; ahora usa `endpoint_path` del record
- `petrel probe --json` mostraba el banner en stdout contaminando el JSON

### Run 2 (2026-07-18)
- 3,485 candidatos nuevos (PyPI 1,972 + GitHub 936 + HF 564 + npm 116 + crt.sh 3)
- 140 MCP servers confirmados — 17 CRITICAL / 31 LOW / 92 INFO
- 134 targets en `targets-v05.yaml` listos para `corvus batch`
- Plataformas: Vercel 14, Railway 10, GCP 7, Fly 6

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
