# Petrel — Siguiente

## Estado: v0.2.0 (2026-07-15) — 33/33 tests ✅

Repo: `github.com/CobaltoSec/petrel` · PyPI: pendiente token

---

## PETREL-V02 — ✅ CERRADO (2026-07-15)

### Resultados D1 — Primer run real

```
crt.sh: 0 dominios (timeout — servicio lento, investigar)
HuggingFace: 564 spaces (4 queries × paginación 500/página)
Censys: skipped (sin credenciales)
Candidates: 562 únicos
Confirmed MCP: 72 servers
  CRITICAL: 1 — amirhashmi017-mcp-server-and-langgraph-agent.hf.space
  LOW: 56 | INFO: 15
```

**CRITICAL encontrado**: `https://amirhashmi017-mcp-server-and-langgraph-agent.hf.space`
- "Unified MCP Server" v1.0.0, 46 tools expuestos, sin auth MCP
- Plataforma: Volvox/Innoscope/Kickstart (SaaS de research/propuestas)
- Tools requieren JWT interno → acceso via `volvox_auth_signup` libre
- Candidato bajo para Ibis (no es execute_bash), pero documenta el patrón

### D2 — ✅ Completado

- **D2a** HF: 4 queries + paginación 500/página → 564 spaces (era 100)
- **D2b** crt.sh: sin filtro de dominio + 4 keywords (timeout pendiente)
- **D2c** Censys: módulo nuevo opcional (`CENSYS_API_ID` + `CENSYS_API_SECRET`)
- **Fix bonus**: `_probe_sse()` ahora llama `_get_tools()` → 45→72 servers (+60%)

### Gotchas registrados

- crt.sh: `%25keyword%25` era double-encoding. Usar `params={"q": keyword}` directo.
- crt.sh: requests concurrentes → rate limit. Usar sequential + `sleep(1.0)`.
- crt.sh: sigue timeout-ing intermitentemente. Issue pendiente (no bloqueante).
- pytest_httpx 0.36.2: no soporta `url__startswith`. Usar `url=re.compile()` + `is_reusable=True`.

---

## Próximo: PETREL-V03

### D3 (siguiente) — `petrel feed-corvus` bridge

Convierte `results.jsonl` (Petrel) → YAML targets para `corvus batch`.

```bash
petrel feed-corvus results.jsonl -o targets.yaml
corvus batch targets.yaml --fast
```

Formato output:
```yaml
- name: "server-name"
  transport: http
  url: "https://..."
  # tags: [petrel-critical, no-auth]
```

Implementar como subcomando en `cli.py`. Filtrar por `is_confirmed_mcp == True`.

### D4 — Review manual de CRITICAL

Después de D1: abrir `results.jsonl`, filtrar `risk_tier == CRITICAL`, revisar manualmente.
- `execute_bash` sin auth → candidato para Ibis advisory
- Documentar en `sectors/red-team/petrel-finds/YYYY-MM-DD-first-run/`

---

## Pendiente manual (Nico)

- **PyPI token**: pypi.org → Account Settings → API tokens → scope `cobaltosec-petrel` → update `~/.pypirc` → `python -m build && .venv/Scripts/twine upload dist/*`
- **Limpiar stub**: `Remove-Item -Recurse -Force "C:\Proyectos\Petrel"`

---

## Roadmap post-V02

| Versión | Foco |
|---------|------|
| V03 | Shodan API (`$49/mo`) — query `http.html:"serverInfo"` + auto-dorks |
| V04 | Active scan via masscan en Kali → httpx filter → petrel probe batch |
| V05 | CobaltoHQ: emit `petrel.server.critical` → Telegram alert |
| V06 | `petrel feed-corvus` full pipeline → SARIF automático |
