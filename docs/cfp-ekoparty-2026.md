# CFP Abstract — Petrel: Semantic MCP Scanner

**Título:** El scanner que ve lo que Shodan no puede: fingerprinting semántico de servidores MCP expuestos
**Título (inglés):** The Scanner That Sees What Shodan Can't: Semantic Fingerprinting of Exposed MCP Servers at Internet Scale

**Track sugerido:** Offensive Security / AI Security / Research
**Formato:** Talk 30–45 min
**Targets:** Ekoparty 2026 (Buenos Aires, deadline 14 agosto) · 8.8 Ecuador (deadline 9 agosto) · NordSec 2026

---

## Estado de la submission

- [x] Run 3 completada — 464 confirmados, 3,948 candidatos, 41 CRITICAL, 106 sin auth (23%)
- [x] Stats actualizadas con números finales de Run 3
- [ ] Grabar fallback video del demo (siempre llevar por si falla red en escenario)
- [ ] Submit a Sessionize

---

## Hook

Censys encontró 21.000 servidores MCP en internet. Saben el IP y el ASN. No saben que 687 de esos servidores ejecutan cualquier bash command que les mandás — sin login, sin API key, sin ninguna autenticación. Nosotros construimos el scanner que extrae qué hace cada servidor hablando el protocolo, no leyendo el puerto.

**Frase para slides:** *"Censys cuenta puertas. Nosotros golpeamos 3.948 y preguntamos qué hay adentro."*

---

## Abstract (español)

MCP (Model Context Protocol) cruzó los 21.000 servidores expuestos en internet en 18 meses, creciendo de cero a infraestructura crítica de AI más rápido que cualquier protocolo anterior. Los scanners de internet existentes —Censys, Shodan, ZMap— pueden localizar estos servidores pero no pueden caracterizar qué hacen. Un port scanner ve un socket; no puede decirte que el servidor detrás ofrece `execute_bash` a clientes no autenticados.

Construimos **Petrel**, un fingerprinter semántico open-source que habla el protocolo MCP JSON-RPC para extraer el inventario completo de tools de cada servidor descubierto, detectar el estado de autenticación, y asignar risk scores por tool. A partir de 3.948 candidatos por descubrimiento pasivo (certificate transparency logs, HuggingFace Spaces, GitHub, npm, Smithery, Shodan, Censys), Petrel confirmó 464 servidores MCP activos en tres runs. De esos, 41 califican CRITICAL y 106 (23%) no implementan ningún mecanismo de autenticación. Combinado con datos de Censys, caracterizamos 687 servidores que ofrecen capacidades de shell execution sin ninguna autenticación, y encontramos que el 91,5% de los servidores Streamable HTTP no tienen OAuth.

Esta charla presenta el pipeline de descubrimiento de Petrel, la metodología de fingerprinting semántico, y la arquitectura de risk scoring por tool. Comparamos nuestros hallazgos contra el trabajo existente de Censys, Knostic y Trend Micro para demostrar qué revela la brecha semántica que el port scanning no puede ver. Cerramos con el pipeline Petrel → Corvus y casos reales de disclosure responsable: 50+ GHSAs filed sobre servidores MCP encontrados por Petrel.

**Demo en vivo (4 actos):**
1. `petrel discover` — candidatos aparecen en tiempo real desde crt.sh, HuggingFace, GitHub, npm
2. `petrel probe <url>` — contra servidor confirmado: tool inventory, auth: none, riesgo CRITICAL. Mismo IP en Censys al lado: solo metadata. El contraste es el punto.
3. El request del atacante — HTTP POST estándar que ejecutaría bash. No lo ejecutamos. Lo mostramos. "Esto no es un ataque sofisticado. Es curl."
4. `petrel feed-corvus → corvus batch` — pipeline completo. Petrel encuentra. Corvus audita.

---

## Abstract (inglés)

MCP (Model Context Protocol) crossed 21,000 internet-exposed deployments in eighteen months, growing from zero to critical AI infrastructure faster than any protocol before it. Existing internet scanners — Censys, Shodan, ZMap — can locate these servers but cannot characterize what they do. A port scanner sees a socket; it cannot tell you that the server behind it offers `execute_bash` to unauthenticated clients.

We built **Petrel**, an open-source semantic fingerprinter that speaks the MCP JSON-RPC protocol to extract the complete tool inventory from each discovered server, detect authentication state, and assign per-tool risk scores. From 3,948 passive discovery candidates (certificate transparency logs, HuggingFace Spaces, GitHub, npm, Smithery, Shodan, Censys), Petrel confirmed 464 live MCP servers across three runs. Of those, 41 score CRITICAL and 106 (23%) implement no authentication mechanism whatsoever. Combined with Censys data, we characterize 687 servers advertising shell execution capabilities with zero authentication, and find 91.5% of Streamable HTTP MCP servers lack OAuth entirely.

This talk presents Petrel's discovery pipeline, semantic fingerprinting methodology, and per-tool risk scoring architecture. We compare our findings against existing census work (Censys, Knostic, Trend Micro) to demonstrate what the semantic gap reveals that port scanning misses. We conclude with the Petrel → Corvus disclosure pipeline and real cases from 50+ GHSAs filed against MCP servers discovered by Petrel.

**Live demo — 4 acts:**
1. `petrel discover` — candidates appear in real time from crt.sh, HuggingFace, GitHub, npm
2. `petrel probe <url>` — against a confirmed server: tool inventory, auth: none, risk CRITICAL. Same IP in Censys side-by-side: just metadata. The contrast is the point.
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

Petrel es el complemento del talk de Corvus ya submiteado: Corvus auditó servidores conocidos. Petrel encontró 464 desconocidos entre 3.948 candidatos. Son el mismo ecosistema desde lados opuestos — discovery vs audit. Dos charlas que se refuerzan mutuamente. El ángulo regional no es geográfico, es de autoría: Petrel y Corvus son herramientas construidas en Argentina presentando research ofensivo de AI security con datos reales de internet.

---

## Speaker bio

Nicolás Padilla — Ingeniero de seguridad, fundador de CobaltoSec (Argentina). Investigación en seguridad de MCP e infraestructura de IA. Autor de Petrel, Corvus, Condor, llamascope-mcp y Merlin — herramientas open-source para auditoría del ecosistema de AI security. 50 GHSAs filed. Corvus: 1.545 descargas/mes.

---

## Materiales

- Tool: `pip install cobaltosec-petrel` — disponible en PyPI
- Repo: github.com/CobaltoSec/petrel — open-source, MIT
- Pipeline: `petrel discover → petrel feed-corvus → corvus batch`
- Demo: requiere conexión a internet para discover live; siempre llevar fallback video
