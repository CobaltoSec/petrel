# Petrel — Siguiente

## Estado: v0.8.0 (2026-07-22) — 237/237 tests ✅

Repo: `github.com/CobaltoSec/petrel` · PyPI: `cobaltosec-petrel v0.6.0` ✅ (v0.8.0 pendiente token)

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
| **PETREL-V08** | Phase 3 — 10 fixes + v0.7.0 | ✅ CERRADO 2026-07-22 |
| **PETREL-CFP-LATAM** | CFP Ekoparty 2026 — abstract + slides + submit Sessionize | ✅ CERRADO 2026-07-22 |
| **PETREL-V09** | Phase 4 — 13 fixes + v0.8.0, 237 tests | ✅ CERRADO 2026-07-22 |
| **PETREL-RUN4** | Run 4 con v0.8.0 → targets-v08.yaml → CS17 | ⏳ próximo |

---

## PETREL-CFP-LATAM — ✅ CERRADO (2026-07-22)

**Ángulo:** "El scanner que ve lo que Shodan no puede" — números globales Run 3.

- D1: Geolocate LATAM (DNS+ip-api.com/batch) → 0 servers LATAM genuinos (CDN FPs). Script: `scripts/latam_stats.py`
- D2: CFP actualizado con Run 3 (3,948/464/41 CRITICAL/23%) → `docs/cfp-ekoparty-2026.md`
- D3: Submitted a Sessionize ✅ — 3/3 slots (Corvus + Condor + Petrel)
- D4 (extra): Slide deck 15 slides + PDF → `Downloads/petrel-ekoparty-2026.html` + `petrel-slides-2026.pdf`

**Notificaciones Ekoparty:** 2026-09-04/11. Conferencia Oct 7-9 Buenos Aires.

---

## PETREL-V09 — ✅ CERRADO (2026-07-22)

**13 fixes Phase 4 backlog → v0.8.0. 212→237 tests.**

- SR-09: CRITICAL tools → exec cluster implícito ✅
- SR-10: Anonymous server signal ✅
- FP-004: Basic auth + X-Api-Key-Required ✅
- FP-006: Per-domain throttling railway/hf.space/fly/onrender/vercel ✅
- FP-011: response_time_ms en MCPServerRecord ✅
- FP-012: probe_error_type (down/timeout/non_mcp/error) ✅
- DISC-010: PyPI chunked gather 50 ✅
- DISC-012: Censys hostname + FOFA host field ✅
- PERF-06: pypi.py shared AsyncClient ✅
- PERF-08: GitHub 4 queries paralelo ✅
- F-06: stats Cloudflare % + tool dist + schema completeness ✅
- F-07: probe failure count en discover/scan summary ✅
- F-08: --markdown + --csv en discover/scan/report ✅

---

## PETREL-RUN4 — ✅ CERRADO (2026-07-24)

**Run 4 con v0.8.0. 4,110 candidatos → 296 confirmados → 39 targets → CS18.**

- D1: `petrel discover` v0.8.0 ✅ — 296 confirmados / 35 CRITICAL / 4 HIGH / 4,110 candidatos
- D2: `petrel diff` results-v07 vs results-v08 ✅ — 3 nuevos, 1 escalado, 193 desaparecidos
- D3: `petrel feed-corvus` → `targets-v08.yaml` ✅ — 39 targets (35 CRITICAL + 4 HIGH) → CS18
- D4: PyPI cobaltosec-petrel v0.8.0 ⏸ deferred — requiere token manual scoped a cobaltosec-petrel

**Bug fix incluido:** `pyproject.toml` 0.7.0 → 0.8.0 (omitido en PETREL-V09)

---

## CS18 — próximo (Corvus)

Corvus batch scan `targets-v08.yaml` (39 targets CRITICAL+HIGH). Bloque en proyecto Corvus.

---

## PETREL-PyPI — pendiente manual

Publicar `cobaltosec-petrel v0.8.0` en PyPI. Requiere token nuevo scoped a `cobaltosec-petrel`.

```bash
python -m build && twine upload dist/cobaltosec_petrel-0.8.0*
```

---

## PETREL-LONGITUDINAL — prerequisites Paper #2 `URGENTE — antes del próximo run`

**Contexto:** Paper #2 (P2-LONGITUDINAL, target ACM IMC 2027) requiere que los runs se puedan joinear entre sí por servidor. Hoy los runs son independientes — no hay cross-run panel. Estos cambios deben implementarse ANTES del próximo `petrel discover` o el run siguiente acumula datos que no se pueden unir al análisis temporal.

### D1 — server_run_snapshots en runs.db

Agregar tabla al schema de `petrel/store.py`:

```sql
CREATE TABLE IF NOT EXISTS server_run_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    url TEXT NOT NULL,
    tool_name_hash TEXT,        -- sha256(sorted(tool_names)), NULL si tools/list falló
    tool_count INTEGER,
    auth_state TEXT,
    risk_tier TEXT,
    priority_score REAL,
    capability_cluster TEXT,    -- JSON array de clusters
    petrel_version TEXT,
    scanned_at TEXT,            -- ISO8601
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_url ON server_run_snapshots(url);
CREATE INDEX IF NOT EXISTS idx_snapshots_run ON server_run_snapshots(run_id);
```

Al finalizar `petrel discover`, insertar un row por cada MCPServerRecord confirmado.

### D2 — tool_signature_hash en MCPServerRecord + JSONL

En `petrel/models.py` (MCPServerRecord), agregar campo:
```python
tool_name_hash: str | None = None  # sha256(sorted([t.name for t in tools]))
```

Computar en `petrel/probe.py` post tools/list:
```python
import hashlib, json
names = sorted(t.name for t in tools)
record.tool_name_hash = hashlib.sha256(json.dumps(names).encode()).hexdigest()[:16]
```

Hash corto (16 chars) para legibilidad. Persistir en JSONL output.

### D3 — capability_cluster + petrel_version al JSONL

`capability_cluster` ya se computa en `risk.py` pero no se persiste al JSONL. Agregar al serializer de MCPServerRecord. También agregar `petrel_version` usando `importlib.metadata.version("cobaltosec-petrel")`.

### D4 — Backfill Runs 5-7 desde JSONL existentes

Script one-shot `scripts/backfill_snapshots.py` que lee los JSONL de Runs 5, 6, 7 (si existen en `~/.petrel/`) e inserta rows en `server_run_snapshots` con `tool_name_hash=NULL` donde no se pueda computar.

Confirmar o documentar pérdida de Runs 1-4 — si los JSONL no están, el finding de los 193 servers desaparecidos no puede ir a una tabla del paper (queda como observación anecdótica en metodología).

### Tests necesarios

- `test_store_snapshots`: insert + query por run_id y url
- `test_tool_name_hash`: mismo set de tools → mismo hash; order-invariant
- `test_jsonl_fields`: capability_cluster y petrel_version presentes en output

**Archivos:** `petrel/store.py`, `petrel/models.py`, `petrel/probe.py`, `petrel/cli.py` (insert en discover), `scripts/backfill_snapshots.py`
