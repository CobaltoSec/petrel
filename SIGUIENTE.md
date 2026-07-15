# Petrel — Siguiente

## Estado: v0.2.0 (2026-07-15) — 33/33 tests ✅

Repo: `github.com/CobaltoSec/petrel` · PyPI: pendiente token

---

## PETREL-V02 — ✅ CERRADO (2026-07-15)

- D1: primer run real — 72 MCP servers confirmados (562 candidates → 72)
- D2a: HF Spaces — 4 queries + paginación 500/página → 564 spaces
- D2b: crt.sh — 4 keywords, sequential sleep(1.0), sin doble-encoding
- D2c: Censys — módulo opcional CENSYS_API_ID/SECRET

---

## PETREL-V03 — ✅ CERRADO (2026-07-15)

### D3 — `petrel feed-corvus` bridge ✅

Convierte `results.jsonl` → YAML targets para `corvus batch`. Filtra SSE-legacy, agrega `/mcp`.

### D4 — Pipeline Petrel→Corvus Run 1 ✅

12 streamable-http targets → 6 con results (6 ERROR no accesibles):
- `arsalan-joiya-gmail-mcp-server`: 9 HIGH, score 100/100 — email injection
- `lambmm-roche-mcp-tools`: 2 HIGH — XHS post injection reflejada en LLM output
- `galcan-mcp-docs-server`: 1 HIGH — reflected XSS "Chunk X not found"
- `amirhashmi017` (46 tools): 2 HIGH — scope creep credential fields

**Conclusión:** Todos HF Spaces personales → no califican Ibis GHSA. Material perfecto para Ekoparty case study.

Resultados en: `corvus/case-studies/petrel-run1/results-full/`

---

## Próximo: PETREL-V04

### Objetivo
Active discovery + Shodan para encontrar MCP servers fuera de HuggingFace.

### D1 — Shodan integration
- Query: `http.html:"serverInfo" AND http.html:"protocolVersion"`
- Alternativa free: `shodan search` CLI (1 query = 100 hosts)
- Requiere `SHODAN_API_KEY`

### D2 — masscan → petrel probe pipeline
- Kali: `masscan 0.0.0.0/0 -p 8000-9000 --rate 10000`
- Filter HTTP → `petrel probe` batch
- Only for private/authorized nets — lab first

### D3 — crt.sh reliability fix
- Investigar rate limit permanente vs timeout intermitente
- Considerar User-Agent header custom
- Alternativa: `crtsh.com` API endpoint alternativo

### D4 — Feed Corvus v2: SSE support
- Corvus batch actualmente solo streamable-http
- Research: Corvus SSE transport support?
- Alternativa: petrel feed → direct HTTP probe sin corvus batch

**Talla: M**
**Dependencias:** Shodan API key opcional (D1), Kali access (D2)

---

## Pendiente manual (Nico)

- **PyPI token**: pypi.org → Account Settings → API tokens → scope `cobaltosec-petrel` → update `~/.pypirc` → `python -m build && .venv/Scripts/twine upload dist/*`
- **Shodan API key**: shodan.io → Account → API key → `SHODAN_API_KEY` en mcp_servers.json

---

## Roadmap

| Versión | Foco |
|---------|------|
| V04 | Active discovery — Shodan + masscan |
| V05 | CobaltoHQ: emit `petrel.server.critical` → Telegram alert |
| V06 | SARIF automático desde pipeline Petrel→Corvus |
