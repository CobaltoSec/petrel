# Petrel — Siguiente

## Estado: v0.4.0 (2026-07-18) — 161/161 tests ✅

Repo: `github.com/CobaltoSec/petrel` · PyPI: pendiente token

---

## PETREL-V05 — ✅ CERRADO (2026-07-18)

### Implementación v0.4.0 (26 items vía workflow paralelo)
- Models: Platform enum, MCPResource/MCPPrompt, nuevos fields, worst_tier variadic
- Discovery: Smithery.ai + PyPI 2-phase + FOFA + GitHub pagination (100→1000)
- Discovery: source tracking correcto en todos los records (`discovered_via`)
- Fingerprint: endpoint_path, capabilities, resources/prompts, platform detection, API_KEY auth
- Scoring: 3 señales (name+desc+schema), clustering, server_name, capabilities, resource URIs
- Output: sarif.py + html.py + cobaltohq.py
- CLI: stats, diff, --source/--resume/--since, bugs fixes

### Run 2 (2026-07-18)
- 3,485 candidatos nuevos → 140 MCP servers confirmados
- 17 CRITICAL sin auth: heym.run, finvestai.top, omi.me, mcp.undisk.app (read_file), glimind.com, +12 más
- 134 targets → `targets-v05.yaml` → Corvus CS16

**Tests:** 46 → 161 ✅ **Pool acumulado:** 212 confirmed (72 Run1 + 140 Run2)

---

## PETREL-V06 — ✅ CERRADO (2026-07-19)

### Objetivo
Mejoras Phase 1 (12 fixes de quality/precision) → v0.5.0. Luego Smithery key + Run 3 post-CS16.

### Phase 1 — implementación paralela (esta sesión)

| ID | Fix | Archivos | Impacto |
|----|-----|----------|---------|
| FP-002 | `serverInfo` → `protocolVersion` como guard de confirmación | probe.py | HIGH |
| FP-003 | 403 Forbidden → `AuthState.REQUIRED` (igual que 401) | probe.py | HIGH |
| FP-001 | JSON-RPC error responses registrados como MCP (no descartados) | probe.py | HIGH |
| PERF-03 | Timeout split: connect=3s / read=8s (antes: 8s plano) | probe.py | HIGH |
| SR-01 | Cluster FS_READ + NETWORK/MESSAGING exfiltration faltante | risk.py | HIGH |
| SR-03 | `query` param → mover a MEDIUM (era FP CRITICAL en search tools) | risk.py | HIGH |
| SR-02 | Fix: tag `no-auth` hardcodeado en feed-corvus independiente de auth_state | cli.py | HIGH |
| F-01+SR-04 | `risk_tier` en todas las entradas + sort CRITICAL-first en targets.yaml | cli.py | MEDIUM |
| DISC-003 | Censys/FOFA query → `"2024-11-05"` (string exclusivo MCP) | censys.py, fofa.py | HIGH |
| DISC-001 | Smithery API key: `SMITHERY_API_KEY` env var + Bearer header + error handling | smithery.py | CRITICAL |
| DISC-004 | crt.sh keyword `mcp` — pre-filter por sufijos de plataformas conocidas | passive.py | HIGH |
| F-02 | CobaltoHQ emite CRITICAL + HIGH (antes solo CRITICAL) | cobaltohq.py | MEDIUM |

### D1 — PyPI publish v0.5.0 (manual — Nico)
Crear token PyPI scoped a `cobaltosec-petrel` en pypi.org.
```bash
python -m build && twine upload dist/cobaltosec_petrel-0.5.0*
```

### D2 — Smithery API key (manual — Nico)
Registrarse en smithery.ai para obtener API key gratuita.
Con DISC-001 implementado: setear `SMITHERY_API_KEY` en env y re-correr.
Potencial: ~6,756 servers nuevos (2x el pool actual).

---

## Phase 2 — próxima sesión inmediata post-CS16

> Implementar antes o después de Run 3 según disponibilidad.

### Discovery
| ID | Fix | Tamaño | Impacto |
|----|-----|--------|---------|
| DISC-002 | URL normalization pre-dedup (trailing slash, http vs https, puertos default) | S | HIGH |
| DISC-008 | Censys cursor pagination (actualmente cap en 100 resultados, hay 500+) | XS | MEDIUM |
| DISC-009 | npm pagination via `from` offset (cap en 250/query, hay 20K+ paquetes MCP) | XS | MEDIUM |
| DISC-011 | Source failures son silenciosas — `SourceResult(urls, warnings, error)` namedtuple | S | MEDIUM |

### Fingerprint
| ID | Fix | Tamaño | Impacto |
|----|-----|--------|---------|
| FP-007 | SSE session path: regex en lugar de `/messages` literal | XS | MEDIUM |
| FP-008 | Tool annotations (`destructive`, `readOnly`) capturadas en MCPTool + scoring | XS | MEDIUM |
| FP-009 | tools/list cursor pagination (servers con 200+ tools bajo-perfilados) | S | MEDIUM |

### Scoring
| ID | Fix | Tamaño | Impacto |
|----|-----|--------|---------|
| SR-05 | Wide-surface CRITICAL FP: 50 getters sin auth ≡ execute_bash. Separar capability_tier vs structural_tier | M | HIGH |
| SR-06 | sampling + FS_READ cross-signal → CRITICAL (exfiltración autónoma LLM) | S | MEDIUM |

### CLI / Pipeline
| ID | Fix | Tamaño | Impacto |
|----|-----|--------|---------|
| F-03 | diff: detectar servers desaparecidos entre runs (tabla "Disappeared") | S | MEDIUM |
| F-04 | diff: detectar tools nuevos en servers existentes (set comparison) | S | MEDIUM |
| PERF-07 | Progress bar durante probe (rich.Progress + ETA) — crítico para 10K candidatos | S | MEDIUM |

### Performance
| ID | Fix | Tamaño | Impacto |
|----|-----|--------|---------|
| PERF-01 | Incremental output: stream JSONL on-the-fly (crash recovery automático con --resume) | M | CRITICAL |
| PERF-02 | Discovery sources en paralelo con asyncio.gather (actualmente serial, 4-8 min overhead) | S | HIGH |

---

## Phase 3 — futuro (post-Run 3)

| ID | Fix | Tamaño | Impacto |
|----|-----|--------|---------|
| DISC-006 | GitHub README parsing — extraer deployment URLs de repos sin homepage | M | HIGH |
| DISC-007 | Shodan: `http.html:"2024-11-05"` — highest-signal internet scanner | M | HIGH |
| DISC-013 | MCP registries: mcp.so, glama.ai, pulsemcp.com | M | MEDIUM |
| FP-005 | tools/list auth check — servers que protegen data plane pero no initialize | S | MEDIUM |
| FP-010 | Nested inputSchema scoring (params peligrosos dentro de objects invisibles) | S | MEDIUM |
| SR-07 | server_instructions scoring (prompt injection patterns, credential leaks) | M | MEDIUM |
| SR-08 | Numeric priority score 0-100 para intra-tier ranking en feed-corvus | M | MEDIUM |
| F-05 | `petrel report` command — regenerar HTML/SARIF desde JSONL existente | S | MEDIUM |
| PERF-04 | probe_urls_batch: chunked gather de 500 (en lugar de N coroutines simultáneas) | M | HIGH |
| PERF-05 | Retry en fingerprint failures (429/503 transientes en Railway/Fly free tier) | S | MEDIUM |

---

## Phase 4 — backlog

| ID | Fix | Tamaño |
|----|-----|--------|
| PERF-06 | pypi.py: un solo httpx.AsyncClient compartido (en lugar de uno por package) | S |
| DISC-010 | PyPI: chunked gather de 50 (en lugar de gather sobre toda la lista) | S |
| SR-09 | Cluster detection: incluir tools con tier CRITICAL como implicit exec-family | S |
| SR-10 | Anonymous server signal (no name, no tools, no auth → explicit flag) | XS |
| FP-004 | Basic auth detection + custom header hints (X-Api-Key-Required) | XS |
| FP-006 | Per-domain throttling (shared hosts: railway.app, hf.space → Semaphore(3)) | M |
| FP-011 | response_time_ms tracking en MCPServerRecord | XS |
| FP-012 | Probe failure classification: down vs non-MCP vs timeout | S |
| DISC-012 | Censys/FOFA: usar hostname en lugar de raw IP:port para virtual hosting | S |
| F-06 | stats: schema completeness %, tool count distribution, Cloudflare % | XS |
| F-07 | Error reporting: probe failure count en summary | XS |
| F-08 | Markdown + CSV output formats | S |
| PERF-08 | GitHub discovery: 4 queries en paralelo (con GITHUB_TOKEN) | S |

---

## Roadmap post-V06

| Bloque | Contenido |
|--------|-----------|
| **CS16** | Corvus batch scan `targets-v05.yaml` (134 targets, 17 CRITICAL) → nuevos GHSAs |
| **PETREL-V06 Run 3** | `petrel discover --since results-v05.jsonl` con Smithery key → 6K+ candidatos → CS17 |
| **PETREL-V07** | Phase 2 improvements + FOFA testing (si creds disponibles) |
| **PETREL-V08** | Phase 3 — Shodan + MCP registries + `petrel watch` modo continuo |
