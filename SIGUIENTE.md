# Petrel — Siguiente

## Estado: v0.6.0 (2026-07-21) — 212/212 tests ✅

Repo: `github.com/CobaltoSec/petrel` · PyPI: `cobaltosec-petrel v0.6.0` ✅

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

## PETREL-V07 — ✅ CERRADO (2026-07-21)

**14 fixes Phase 2 implementados vía workflow paralelo (6 agentes). 177 → 208 tests.**

- DISC-002: URL normalization pre-dedup ✅
- DISC-008: Censys cursor pagination 100→500 ✅
- DISC-009: npm offset pagination 250→1000/query ✅
- DISC-011: `SourceResult` namedtuple — errores de sources visibles ✅
- PERF-02: Discovery sources paralelo (`asyncio.gather`) ✅
- FP-007: SSE session path regex ✅
- FP-008: Tool annotations capturadas (`destructive`/`readOnly`) ✅
- FP-009: `tools/list` cursor pagination ✅
- SR-05: Wide-surface CRITICAL FP fix (capability_tier vs structural_tier) ✅
- SR-06: sampling + FS_READ → CRITICAL ✅
- PERF-01: Incremental JSONL output (crash recovery) ✅
- PERF-07: Rich progress bar con ETA ✅
- F-03: diff muestra servers desaparecidos ✅
- F-04: diff muestra tools nuevas en servers existentes ✅

**PyPI:** `cobaltosec-petrel v0.5.0` + `v0.6.0` publicados ✅
**Pendiente manual:** Smithery API key (registrar en smithery.ai → Run 3 con ~6,756 candidatos)

---

## Phase 3 — PETREL-V08 (próximo bloque)

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

## Roadmap

| Bloque | Contenido | Estado |
|--------|-----------|--------|
| **CS16** | Corvus batch scan `targets-v05.yaml` | ✅ CERRADO 2026-07-20 |
| **PETREL-V07** | Phase 2 — 14 fixes + PyPI v0.6.0 | ✅ CERRADO 2026-07-21 |
| **PETREL-RUN3** | Smithery API fix + Run 3: 464 confirmados, targets-v07.yaml → CS17 | ✅ CERRADO 2026-07-21 |
| **PETREL-V08** | Phase 3 — Shodan + MCP registries + `petrel watch` | pendiente |

---

## Ekoparty 2026 — CFP Petrel (deadline: 7 agosto para tener margen)

**Estado:** borrador listo en `docs/cfp-ekoparty-2026.md`. Slot 3 disponible en Sessionize (slot 1 = Corvus ✅, slot 2 = Condor ✅).

**Ángulo del talk:** "El scanner que ve lo que Shodan no puede" — dato LATAM-específico fortalece el ángulo regional para Ekoparty Buenos Aires.

**Bloqueante para submit:** Run 3 con filtro LATAM — sin datos regionales el abstract pierde el ángulo geográfico.

### Run 3 — LATAM scan (desbloquea CFP submit)

**Run 3 completada (2026-07-21):** 464 confirmados, 41 CRITICAL, Smithery aportó 45 servers reales (38% conversión). `targets-v07.yaml` listo para CS17.

**Pendiente para CFP:** filtro geolocation LATAM (AR/BR/MX/CO/CL) vía IP sobre `results-v07.jsonl` → estadísticas regionales → actualizar `docs/cfp-ekoparty-2026.md` → submit Sessionize.

| Paso | Acción |
|------|--------|
| 1 | `petrel stats results-v07.jsonl` + geolocate IPs con MaxMind/ipapi → filtrar LATAM |
| 2 | Agregar dato LATAM al CFP abstract (`docs/cfp-ekoparty-2026.md`) |
| 3 | Submit a Sessionize antes del 7 agosto |
