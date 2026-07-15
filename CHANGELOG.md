# Changelog

## [Unreleased]

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
