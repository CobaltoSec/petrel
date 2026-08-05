# CFP Abstract — Petrel: Semantic MCP Scanner

**Título:** El scanner que ve lo que Shodan no puede: fingerprinting semántico de servidores MCP expuestos
**Título (inglés):** The Scanner That Sees What Shodan Can't: Semantic Fingerprinting of Exposed MCP Servers at Internet Scale

**Track sugerido:** Offensive Security / AI Security / Research
**Formato:** Session (30–45 min) — ⚠️ submiteado como Lightning talk, cambiar a Session antes 14 Aug
**Targets:** Ekoparty 2026 (Buenos Aires, deadline 14 agosto) · 8.8 Ecuador (deadline 9 agosto) · NordSec 2026

---

## Estado de la submission

- [x] Run 7 completada — 462 confirmados, 42 CRITICAL (2026-08-03)
- [x] Run 6 anterior — 445 confirmados, 41 CRITICAL (2026-07-31)
- [x] Stats actualizadas con números de última run
- [x] Slides actualizados (Run 7) + PDF exportado
- [ ] Grabar fallback video del demo (siempre llevar por si falla red en escenario)
- [x] ✅ SUBMITEADO en Sessionize — en evaluación

---

## Estado actual en Sessionize (snapshot 2026-08-05)

Lo que está live ahora:
- Format: Lightning talk (debe cambiarse a Session)
- "3.948 candidatos / 464 confirmados / 41 CRITICAL / 106 sin auth / 50+ GHSAs"
- Pool acumulado: "~640 servers"
- Slides subidos: `petrel-slides-2026.pdf` (stats desactualizadas)
- Outline: "Run 3: 464 confirmados, 41 CRITICAL, 23% sin auth. Pool ~640."

## Edits pendientes para Sessionize (antes 14 Aug)

| Campo | Dice ahora | Cambiar a |
|-------|-----------|-----------|
| Session format | Lightning talk | **Session** |
| candidatos | 3.948 | 4.100+ |
| confirmados | 464 | 462 |
| CRITICAL | 41 | 42 |
| GHSAs | 50+ | 174 |
| Pool acumulado | ~640 | 700+ |
| Run 3 (outline) | 464 / 41 CRITICAL / 23% | 462 / 42 CRITICAL / 23% |
| Primer párrafo | empieza con "MCP cruzó los 21.000..." | arrancar con los 687 bash sin auth |
| Slides | petrel-slides-2026.pdf | petrel-ekoparty-2026-slides.pdf (Run 7) |

---

## Hook

Censys encontró 21.000 servidores MCP en internet. Saben el IP y el ASN. No saben que 687 de esos servidores ejecutan cualquier bash command que les mandás — sin login, sin API key, sin ninguna autenticación. Nosotros construimos el scanner que extrae qué hace cada servidor hablando el protocolo, no leyendo el puerto.

**Frase para slides:** *"Censys cuenta puertas. Nosotros golpeamos 4.100 y preguntamos qué hay adentro."*

---

## Abstract (español)

21.000 servidores MCP expuestos en internet. Censys sabe el IP y el ASN. No sabe que 687 de esos servidores ejecutan cualquier bash command que les mandás — sin login, sin API key, sin token. Un port scanner ve un socket. No puede decirte lo que hay adentro. Nosotros construimos el scanner que habla el protocolo y extrae qué hace cada servidor, uno por uno.

Construimos **Petrel**, un fingerprinter semántico open-source que habla el protocolo MCP JSON-RPC para extraer el inventario completo de tools de cada servidor descubierto, detectar el estado de autenticación, y asignar risk scores por tool. A partir de 4.100+ candidatos por descubrimiento pasivo (certificate transparency logs, HuggingFace Spaces, GitHub, npm, Smithery, Shodan, Censys), Petrel confirmó 462 servidores MCP activos en la última run (2026-08-03), con un pool acumulado de 700+ servidores únicos a través de todas las corridas. De esos, 42 califican CRITICAL y más del 23% no implementan ningún mecanismo de autenticación. Combinado con datos de Censys, caracterizamos 687 servidores que ofrecen capacidades de shell execution sin ninguna autenticación, y encontramos que el 91,5% de los servidores Streamable HTTP no tienen OAuth.

Esta charla presenta el pipeline de descubrimiento de Petrel, la metodología de fingerprinting semántico, y la arquitectura de risk scoring por tool. Comparamos nuestros hallazgos contra el trabajo existente de Censys, Knostic y Trend Micro para demostrar qué revela la brecha semántica que el port scanning no puede ver. Cerramos con el pipeline Petrel → Corvus y casos reales de disclosure responsable: 174 GHSAs filed sobre servidores MCP encontrados por Petrel. Esta investigación forma parte del paper "Exposed by Design" (arXiv:2608.00150, cs.CR).

**Demo en vivo (4 actos):**
1. `petrel discover` — candidatos aparecen en tiempo real desde crt.sh, HuggingFace, GitHub, npm
2. `petrel probe TARGET` — contra servidor confirmado: tool inventory, auth: none, riesgo CRITICAL. Mismo IP en Censys al lado: solo metadata. El contraste es el punto.
3. El request del atacante — HTTP POST estándar que ejecutaría bash. No lo ejecutamos. Lo mostramos. "Esto no es un ataque sofisticado. Es curl."
4. `petrel feed-corvus → corvus batch` — pipeline completo. Petrel encuentra. Corvus audita.

---

## Abstract (inglés)

21,000 MCP servers exposed on the internet. Censys knows the IP and the ASN. It doesn't know that 687 of those servers will execute any bash command you send them — no login, no API key, no token. A port scanner sees a socket. It cannot tell you what's inside. We built the scanner that speaks the protocol and extracts what each server does, one by one.

We built **Petrel**, an open-source semantic fingerprinter that speaks the MCP JSON-RPC protocol to extract the complete tool inventory from each discovered server, detect authentication state, and assign per-tool risk scores. From 4,100+ passive discovery candidates (certificate transparency logs, HuggingFace Spaces, GitHub, npm, Smithery, Shodan, Censys), Petrel confirmed 462 live MCP servers in the latest run (2026-08-03), with a cumulative pool of 700+ unique servers across all runs. Of those, 42 score CRITICAL and more than 23% implement no authentication mechanism whatsoever. Combined with Censys data, we characterize 687 servers advertising shell execution capabilities with zero authentication, and find 91.5% of Streamable HTTP MCP servers lack OAuth entirely.

This talk presents Petrel's discovery pipeline, semantic fingerprinting methodology, and per-tool risk scoring architecture. We compare our findings against existing census work (Censys, Knostic, Trend Micro) to demonstrate what the semantic gap reveals that port scanning misses. We conclude with the Petrel → Corvus disclosure pipeline and real cases from 174 GHSAs filed against MCP servers discovered by Petrel. This research is part of "Exposed by Design" (arXiv:2608.00150, cs.CR).

**Live demo — 4 acts:**
1. `petrel discover` — candidates appear in real time from crt.sh, HuggingFace, GitHub, npm
2. `petrel probe TARGET` — against a confirmed server: tool inventory, auth: none, risk CRITICAL. Same IP in Censys side-by-side: just metadata. The contrast is the point.
3. The attacker's request — standard HTTP POST that would execute bash. We don't run it. We show it. "This is not a sophisticated attack. It's curl."
4. `petrel feed-corvus → corvus batch` — full pipeline. Petrel finds. Corvus audits.

---

## Diferenciación vs. trabajo existente

| Investigación | Qué hace | Qué no hace |
|---------------|----------|-------------|
| Censys (abril 2026) | Encuentra 21K servers por IP/ASN | No sabe qué tools expone cada uno |
| Knostic | Verifica 119 servers manualmente | Sin dynamic risk scoring, sin pipeline |
| Trend Micro | Encuentra 492 sin auth | Sin tool-level fingerprinting |
| **Petrel** | Habla MCP, extrae inventario, score por tool, pipeline a Corvus | — |

---

## Por qué Ekoparty es el venue ideal

Petrel es el complemento del talk de Corvus ya submiteado: Corvus auditó servidores conocidos. Petrel encontró 462 confirmados entre 4.100+ candidatos. Son el mismo ecosistema desde lados opuestos — discovery vs audit. Dos charlas que se refuerzan mutuamente. El ángulo regional no es geográfico, es de autoría: Petrel y Corvus son herramientas construidas en Argentina presentando research ofensivo de AI security con datos reales de internet.

---

## Speaker bio

Nicolás Padilla — Ingeniero de seguridad, fundador de CobaltoSec (Argentina). Investigación en seguridad de MCP e infraestructura de IA. Autor de Petrel, Corvus, Condor y Merlin — herramientas open-source para auditoría del ecosistema de AI security. **174 GHSAs filed (37 publicados)**. Paper publicado en arXiv cs.CR: "Exposed by Design" (arXiv:2608.00150).

---

## Materiales

- Tool: `pip install cobaltosec-petrel` — disponible en PyPI
- Repo: github.com/CobaltoSec/petrel — open-source, MIT
- Pipeline: `petrel discover → petrel feed-corvus → corvus batch`
- Paper: arXiv:2608.00150 — "Exposed by Design: A Dynamic Security Assessment of Internet-Facing MCP Servers at Scale" (cs.CR, 2026-08-04)
- Slides: `docs/slides/petrel-ekoparty-2026-slides.html` + `docs/slides/petrel-ekoparty-2026-slides.pdf` (15 slides, 16:9, 289KB — stats actualizados Run 7)
- Demo: requiere conexión a internet para discover live; siempre llevar fallback video
