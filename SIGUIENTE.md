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

## Próximo: PETREL-V06

### Objetivo
Publicar PyPI + Smithery API key + Run 3 post-CS16.

### D1 — PyPI publish (manual — Nico)
Crear token PyPI scoped a `cobaltosec-petrel` en pypi.org.
```bash
python -m build && twine upload dist/cobaltosec_petrel-0.4.0*
```

### D2 — Smithery API key
Registrarse en smithery.ai para obtener API key gratuita.
Run 2 retornó 0 resultados — con key: acceso a catálogo completo (~6,756 servers).
Agregar como `SMITHERY_API_KEY` en la llamada + pasar en header Authorization.

### D3 — Run 3 post-CS16 (operacional)
Después de Corvus CS16 (auditoría de targets-v05.yaml):
```bash
petrel discover --output results-v06.jsonl --since results-v05.jsonl --sarif results-v06.sarif
petrel diff results-v05.jsonl results-v06.jsonl
petrel feed-corvus results-v06.jsonl --output targets-v06.yaml --source github
```
Foco: plataformas cloud (Vercel/Railway/GCP/Fly) — mayor probabilidad de findings GHSA.

### D4 — FOFA testing (condicional)
Si conseguimos FOFA_EMAIL + FOFA_KEY gratuitos: validar cobertura Asian cloud (Alibaba/Tencent/Huawei).

**Talla: S** (D1+D2 son manuales; D3 operacional)
**Dependencias:** D3 depende de Corvus CS16

---

## Roadmap

| Versión | Foco |
|---------|------|
| V06 | PyPI publish + Smithery key + Run 3 post-CS16 |
| V07 | FOFA cobertura Asian cloud (si creds disponibles) |
| V08 | `petrel watch` — modo continuo, emite CobaltoHQ on new CRITICAL |
