# Petrel — Siguiente

## Estado: v0.1.0 bootstrapped (2026-07-15)

Repo: `github.com/CobaltoSec/petrel` · PyPI: pendiente · 21/21 tests ✅

---

## Pendiente inmediato

### PyPI publish
Generar token en pypi.org → Account Settings → API tokens → scope `cobaltosec-petrel`.
Actualizar `~/.pypirc` y correr:
```bash
cd tools/petrel && python -m build && .venv/Scripts/twine upload dist/*
```

### Limpieza
Eliminar `C:\Proyectos\Petrel\` (stub vacío, Windows lock):
```powershell
Remove-Item -Recurse -Force "C:\Proyectos\Petrel"
```

---

## Próximos bloques

### PETREL-V02 — Primer discover real
- Correr `petrel discover -o results.jsonl` y documentar hallazgos
- Cuántos servers reales confirmados, cuántos CRITICAL
- Material para disclosure si hay `execute_bash` sin auth
- Potencial blog post / Ekoparty material

### PETREL-V03 — Shodan integration
- Agregar `petrel discover --shodan` usando Shodan API (opcional, $49/mes)
- Query: `http.html:"serverInfo" port:8080` + pattern MCP
- Genera dorks automáticas desde resultados locales

### PETREL-V04 — Active scan (Kali)
- `petrel discover --range <CIDR>` via masscan en Kali
- Pipeline: masscan → httpx filter → petrel probe batch

### PETREL-V05 — CobaltoHQ integration
- Emit `petrel.server.discovered` → fleet_events con payload {url, risk_tier, tools[]}
- Emit `petrel.server.critical` si risk_tier == CRITICAL → Telegram alert

### PETREL-V06 — Feed a Corvus
- `petrel feed-corvus results.jsonl` → formato batch input para Corvus
- Pipeline completo: discover → score → audit → SARIF
