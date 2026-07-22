#!/usr/bin/env python3
"""latam_stats.py — LATAM MCP server stats from results JSONL (Ekoparty CFP).

Usage: python scripts/latam_stats.py [results.jsonl]
Default: results-v07.jsonl in CWD

Dependencies: httpx (already in petrel venv)
"""
import json
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import httpx

LATAM_COUNTRIES = {
    "AR": "Argentina",
    "BR": "Brasil",
    "MX": "México",
    "CO": "Colombia",
    "CL": "Chile",
    "PE": "Perú",
    "UY": "Uruguay",
    "VE": "Venezuela",
    "EC": "Ecuador",
    "BO": "Bolivia",
    "PY": "Paraguay",
}

# These platforms resolve to CDN/cloud IPs, not the operator's infra → skip
SHARED_PLATFORMS = {
    "huggingface",
    "vercel",
    "railway",
    "fly.io",
    "gcp",
    "aws-lambda",
    "azure",
    "cloudflare-workers",
    "render",
}

GEO_API = "http://ip-api.com/batch"


def load_records(path: Path) -> list[dict]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def extract_host(url: str) -> str:
    return urlparse(url).hostname or ""


def geolocate(hosts: list[str], chunk_size: int = 100) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    chunks = [hosts[i : i + chunk_size] for i in range(0, len(hosts), chunk_size)]
    for idx, chunk in enumerate(chunks):
        print(f"  [geo] chunk {idx + 1}/{len(chunks)} ({len(chunk)} hosts)...", end=" ", flush=True)
        try:
            resp = httpx.post(
                GEO_API,
                json=[{"query": h} for h in chunk],
                timeout=30,
            )
            resp.raise_for_status()
            for item in resp.json():
                host = item.get("query", "")
                result[host] = item.get("countryCode") if item.get("status") == "success" else None
            print("ok")
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            for h in chunk:
                result[h] = None
        if idx < len(chunks) - 1:
            time.sleep(2)
    return result


def print_report(all_records: list[dict], geolocatable: list[dict], latam_records: list[dict]) -> None:
    total = len(all_records)
    n = len(latam_records)
    no_auth_global = sum(1 for r in all_records if r.get("auth_state") == "none")
    critical_global = sum(1 for r in all_records if r.get("risk_tier") == "CRITICAL")

    print(f"\n{'=' * 60}")
    print("PETREL RUN 3 — GLOBAL STATS")
    print(f"{'=' * 60}")
    print(f"Candidatos escaneados:    3,948")
    print(f"MCP servers confirmados:  {total}")
    print(f"Sin autenticación:        {no_auth_global} ({100 * no_auth_global / total:.0f}%)")
    print(f"CRITICAL:                 {critical_global}")
    print(f"Geolocateables (custom):  {len(geolocatable)}")

    print(f"\n{'=' * 60}")
    print("LATAM MCP SERVER STATS")
    print(f"{'=' * 60}")

    if not latam_records:
        print("No LATAM servers found in geolocatable records.")
        return

    no_auth = sum(1 for r in latam_records if r.get("auth_state") == "none")
    by_country: Counter = Counter(r["_country"] for r in latam_records)
    by_tier: Counter = Counter(r.get("risk_tier") for r in latam_records)
    critical_high = by_tier.get("CRITICAL", 0) + by_tier.get("HIGH", 0)

    print(f"Servidores LATAM:  {n} ({100 * n / total:.1f}% del total global)")
    print()
    print("Por país:")
    for code, count in by_country.most_common():
        name = LATAM_COUNTRIES.get(code, code)
        print(f"  {name} ({code}): {count}")
    print()
    print("Risk tier (LATAM):")
    for tier in ["CRITICAL", "HIGH", "LOW", "INFO"]:
        c = by_tier.get(tier, 0)
        if c:
            print(f"  {tier}: {c}")
    print()
    print(f"Sin autenticación: {no_auth}/{n} ({100 * no_auth / n:.0f}%)" if n else "")

    # CFP copy-paste block
    print(f"\n{'--- CFP COPY-PASTE ':-<60}")
    countries_str = ", ".join(
        f"{LATAM_COUNTRIES.get(c, c)} ({cnt})"
        for c, cnt in by_country.most_common()
    )
    print(
        f"De los {total} servidores MCP confirmados (sobre 3,948 candidatos), "
        f"{n} se encuentran en América Latina ({countries_str}). "
        f"El {100 * no_auth / n:.0f}% no implementa ningún mecanismo de autenticación."
    )
    if critical_high:
        print(f"Del total regional, {critical_high} presentan riesgo CRITICAL o HIGH.")
    print("-" * 60)


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results-v07.jsonl")
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {path}...")
    all_records = load_records(path)
    print(f"[*] {len(all_records)} records loaded")

    geolocatable = [
        r for r in all_records
        if r.get("platform", "unknown") not in SHARED_PLATFORMS
    ]
    skipped = len(all_records) - len(geolocatable)
    print(f"[*] Geolocatable: {len(geolocatable)} (skipping {skipped} shared-platform records)")

    unique_hosts = list({extract_host(r["url"]) for r in geolocatable if extract_host(r["url"])})
    print(f"[*] Unique hosts: {len(unique_hosts)} → {(len(unique_hosts) - 1) // 100 + 1} batch request(s)")

    print("[*] Geolocating via ip-api.com/batch...")
    geo = geolocate(unique_hosts)

    latam_records = []
    for r in geolocatable:
        country = geo.get(extract_host(r["url"]))
        if country in LATAM_COUNTRIES:
            latam_records.append({**r, "_country": country})

    print_report(all_records, geolocatable, latam_records)


if __name__ == "__main__":
    main()
