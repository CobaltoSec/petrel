# Petrel

**MCP Internet Scanner & Fingerprinter** — find exposed MCP servers before attackers do.

```
petrel discover                     # passive: crt.sh + HuggingFace Spaces
petrel probe https://target.com     # fingerprint a single server
petrel scan targets.txt             # batch from file
```

## Install

```bash
pip install cobaltosec-petrel
```

## What it finds

Petrel probes MCP servers via their JSON-RPC handshake, extracts the full tool inventory, detects auth state, and scores risk:

- `execute_bash` without auth → **CRITICAL**
- `write_file` without auth → **HIGH**
- `read_file` without auth → **MEDIUM**

Unlike Shodan, Petrel understands MCP semantics — not just "port open" but "this server exposes shell execution with no authentication."

## Discovery sources (no API key required)

- **crt.sh** — certificate transparency logs
- **HuggingFace Spaces** — public MCP server deployments

## Pipeline with Corvus

```bash
petrel discover -o results.jsonl
# feed into Corvus for deep security audit
```

## Part of the CobaltoSec ecosystem

[CobaltoSec](https://cobalto-sec.tech) · [Corvus](https://github.com/CobaltoSec/corvus) · [Kestrel](https://github.com/CobaltoSec/kestrel)
