"""Petrel CLI — MCP Internet Scanner & Fingerprinter."""
from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .discovery.censys import censys_search
from .discovery.fofa import fofa_search
from .discovery.github import github_search
from .discovery.npm import npm_search
from .discovery.passive import crtsh_search, hf_spaces_search
from .discovery.pypi import pypi_search
from .discovery.smithery import smithery_search
from .fingerprint.probe import probe_url, probe_urls_batch
from .models import MCPServerRecord, RiskTier
from .scoring.risk import score_server

app = typer.Typer(
    name="petrel",
    help="MCP Internet Scanner & Fingerprinter — find exposed MCP servers.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True)

_BANNER = f"""\
[bold cyan]
    ____       __           __
   / __ \\___  / /_________  / /
  / /_/ / _ \\/ __/ ___/ _ \\/ /
 / ____/  __/ /_/ /  /  __/ /
/_/    \\___/\\__/_/   \\___/_/
[/bold cyan][dim]v{__version__} · MCP Internet Scanner[/dim]
"""

_TIER_COLOR = {
    RiskTier.CRITICAL: "red",
    RiskTier.HIGH: "orange3",
    RiskTier.MEDIUM: "yellow",
    RiskTier.LOW: "green",
    RiskTier.INFO: "dim",
}

_TIER_ORDER = list(RiskTier)


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

@app.command()
def probe(
    url: Annotated[str, typer.Argument(help="URL to fingerprint")],
    json_out: Annotated[bool, typer.Option("--json", "-j", help="JSON output")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save results to file")] = None,
) -> None:
    """Fingerprint a single MCP server URL."""
    # C9: suppress banner when --json is set
    if not json_out:
        console.print(_BANNER)

    import httpx

    async def _run() -> MCPServerRecord | None:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            return await probe_url(url, client)

    result = asyncio.run(_run())

    if result is None:
        err.print(f"[red]No MCP server detected at {url}[/red]")
        raise typer.Exit(1)

    result = score_server(result)

    if json_out:
        data = result.model_dump(mode="json")
        print(json.dumps(data, default=str))
        return

    _print_server(result)

    data = result.model_dump(mode="json")
    if output:
        output.write_text(json.dumps(data, indent=2, default=str))
        console.print(f"\n[dim]Saved to {output}[/dim]")


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------

@app.command()
def discover(
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save results (JSONL)")] = None,
    no_probe: Annotated[bool, typer.Option("--no-probe", help="Skip fingerprinting, list URLs only")] = False,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c")] = 20,
    no_censys: Annotated[bool, typer.Option("--no-censys", help="Skip Censys even if credentials are set")] = False,
    no_github: Annotated[bool, typer.Option("--no-github", help="Skip GitHub search")] = False,
    no_npm: Annotated[bool, typer.Option("--no-npm", help="Skip npm registry search")] = False,
    no_smithery: Annotated[bool, typer.Option("--no-smithery", help="Skip Smithery.ai search")] = False,
    no_pypi: Annotated[bool, typer.Option("--no-pypi", help="Skip PyPI package search")] = False,
    no_fofa: Annotated[bool, typer.Option("--no-fofa", help="Skip FOFA search")] = False,
    resume: Annotated[Optional[Path], typer.Option("--resume", help="JSONL with already-confirmed URLs to skip")] = None,
    since: Annotated[Optional[Path], typer.Option("--since", help="Previous results JSONL — skip already-discovered candidates")] = None,
    sarif_out: Annotated[Optional[Path], typer.Option("--sarif", help="Save SARIF 2.1.0 report")] = None,
    html_out: Annotated[Optional[Path], typer.Option("--html", help="Save HTML report")] = None,
) -> None:
    """Discover exposed MCP servers via passive sources (crt.sh + HuggingFace + Censys + GitHub + npm + Smithery + PyPI + FOFA)."""
    console.print(_BANNER)

    async def _run() -> list[MCPServerRecord]:
        import httpx

        # C1: collect (url, source) pairs from each source
        url_sources: list[tuple[str, str]] = []

        with console.status("[cyan]Querying crt.sh (4 keywords)..."):
            crt_domains = await crtsh_search()
            crt_urls = [f"https://{d}" for d in crt_domains]
        url_sources.extend((u, "crtsh") for u in crt_urls)
        console.print(f"  [green]crt.sh[/green]: {len(crt_domains)} domains")

        with console.status("[cyan]Querying HuggingFace Spaces (4 queries, paginated)..."):
            hf_urls = await hf_spaces_search()
        url_sources.extend((u, "huggingface") for u in hf_urls)
        console.print(f"  [green]HuggingFace[/green]: {len(hf_urls)} spaces")

        if not no_censys:
            import os
            has_creds = bool(os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET"))
            if has_creds:
                with console.status("[cyan]Querying Censys..."):
                    censys_urls = await censys_search()
                url_sources.extend((u, "censys") for u in censys_urls)
                console.print(f"  [green]Censys[/green]: {len(censys_urls)} hosts")
            else:
                console.print("  [dim]Censys: skipped (no CENSYS_API_ID/CENSYS_API_SECRET)[/dim]")

        if not no_github:
            with console.status("[cyan]Querying GitHub (4 queries, rate-limited)..."):
                github_urls = await github_search()
            url_sources.extend((u, "github") for u in github_urls)
            console.print(f"  [green]GitHub[/green]: {len(github_urls)} repos with deployment URLs")

        if not no_npm:
            with console.status("[cyan]Querying npm registry (4 queries)..."):
                npm_urls = await npm_search()
            url_sources.extend((u, "npm") for u in npm_urls)
            console.print(f"  [green]npm[/green]: {len(npm_urls)} packages with deployment URLs")

        # C7: Smithery
        if not no_smithery:
            import os as _os
            _smithery_key = _os.getenv("SMITHERY_API_KEY")
            with console.status("[cyan]Querying Smithery.ai registry (paginated)..."):
                smithery_urls = await smithery_search(api_key=_smithery_key)
            url_sources.extend((u, "smithery") for u in smithery_urls)
            if _smithery_key:
                console.print(f"  [green]Smithery[/green]: {len(smithery_urls)} servers")
            else:
                console.print(f"  [dim]Smithery[/dim]: {len(smithery_urls)} servers [dim](set SMITHERY_API_KEY for full access ~6,756)[/dim]")

        # C7: PyPI
        if not no_pypi:
            with console.status("[cyan]Querying PyPI package index..."):
                pypi_urls = await pypi_search()
            url_sources.extend((u, "pypi") for u in pypi_urls)
            console.print(f"  [green]PyPI[/green]: {len(pypi_urls)} packages with deployment URLs")

        # C7: FOFA
        if not no_fofa:
            import os
            has_fofa = bool(os.getenv("FOFA_EMAIL") and os.getenv("FOFA_KEY"))
            if has_fofa:
                with console.status("[cyan]Querying FOFA..."):
                    fofa_urls = await fofa_search()
                url_sources.extend((u, "fofa") for u in fofa_urls)
                console.print(f"  [green]FOFA[/green]: {len(fofa_urls)} hosts")
            else:
                console.print("  [dim]FOFA: skipped (no FOFA_EMAIL/FOFA_KEY)[/dim]")

        # C1: build source_map (first-seen wins on dedup)
        source_map: dict[str, str] = {}
        for url, src in url_sources:
            if url not in source_map:
                source_map[url] = src
        urls = list(source_map.keys())

        # C6: --since deduplication
        if since and since.exists():
            prev_urls: set[str] = set()
            for line in since.read_text().splitlines():
                line = line.strip()
                if line:
                    r = json.loads(line)
                    prev_urls.add(r["url"])
                    if r.get("final_url"):
                        prev_urls.add(r["final_url"])
            before = len(urls)
            urls = [u for u in urls if u not in prev_urls]
            console.print(f"[dim]--since: {before - len(urls)} already known, {len(urls)} new candidates[/dim]")

        # C5: --resume (skip already-confirmed)
        if resume and resume.exists():
            seen_urls = {
                json.loads(line)["url"]
                for line in resume.read_text().splitlines()
                if line.strip()
            }
            before = len(urls)
            urls = [u for u in urls if u not in seen_urls]
            console.print(f"[dim]Resume: skipping {len(seen_urls)} already-confirmed, {len(urls)} remaining[/dim]")

        console.print(f"\n[bold]Candidates:[/bold] {len(urls)}")

        # C2: --no-probe saves URL list to file
        if no_probe:
            if output:
                output.write_text("\n".join(urls))
                console.print(f"[dim]{len(urls)} candidates saved to {output}[/dim]")
            else:
                for u in urls:
                    console.print(f"  {u}")
            return []

        console.print("[cyan]Fingerprinting...[/cyan]")
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            raw = await probe_urls_batch(urls, client, concurrency=concurrency, source_map=source_map)

        confirmed = [score_server(r) for r in raw if r is not None and r.is_confirmed_mcp]
        return confirmed

    records = asyncio.run(_run())

    if records:
        _print_summary(records)

    if output and records:
        with output.open("w") as f:
            for r in records:
                f.write(json.dumps(r.model_dump(mode="json"), default=str) + "\n")
        console.print(f"\n[dim]Results saved to {output}[/dim]")

    # C8: SARIF + HTML output
    if sarif_out and records:
        from .output.sarif import write_sarif
        write_sarif(records, sarif_out)
        console.print(f"[dim]SARIF saved to {sarif_out}[/dim]")
    if html_out and records:
        from .output.html import write_html
        write_html(records, html_out)
        console.print(f"[dim]HTML report saved to {html_out}[/dim]")

    # Always emit critical events to CobaltoHQ
    from .output.cobaltohq import emit_critical_servers
    n_emitted = emit_critical_servers(records)
    if n_emitted:
        console.print(f"[dim]CobaltoHQ: {n_emitted} high-risk events emitted[/dim]")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    targets: Annotated[Path, typer.Argument(help="File with URLs, one per line")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c")] = 20,
    min_risk: Annotated[str, typer.Option("--min-risk")] = "INFO",
    sarif_out: Annotated[Optional[Path], typer.Option("--sarif", help="Save SARIF 2.1.0 report")] = None,
    html_out: Annotated[Optional[Path], typer.Option("--html", help="Save HTML report")] = None,
) -> None:
    """Batch fingerprint MCP servers from a targets file."""
    console.print(_BANNER)

    if not targets.exists():
        err.print(f"[red]File not found: {targets}[/red]")
        raise typer.Exit(1)

    urls = [l.strip() for l in targets.read_text().splitlines() if l.strip() and not l.startswith("#")]
    console.print(f"[cyan]Scanning {len(urls)} targets (concurrency={concurrency})...[/cyan]")

    import httpx

    async def _run() -> list[MCPServerRecord]:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            raw = await probe_urls_batch(urls, client, concurrency=concurrency)
        return [score_server(r) for r in raw if r is not None and r.is_confirmed_mcp]

    records = asyncio.run(_run())

    min_risk_upper = min_risk.upper()
    if min_risk_upper in RiskTier._value2member_map_:
        min_idx = _TIER_ORDER.index(RiskTier(min_risk_upper))
        filtered = [r for r in records if _TIER_ORDER.index(r.risk_tier) <= min_idx]
    else:
        filtered = records

    _print_summary(filtered)

    if output and filtered:
        with output.open("w") as f:
            for r in filtered:
                f.write(json.dumps(r.model_dump(mode="json"), default=str) + "\n")
        console.print(f"\n[dim]Saved to {output}[/dim]")

    # C8: SARIF + HTML
    if sarif_out and filtered:
        from .output.sarif import write_sarif
        write_sarif(filtered, sarif_out)
        console.print(f"[dim]SARIF saved to {sarif_out}[/dim]")
    if html_out and filtered:
        from .output.html import write_html
        write_html(filtered, html_out)
        console.print(f"[dim]HTML report saved to {html_out}[/dim]")

    # Always emit critical events to CobaltoHQ
    from .output.cobaltohq import emit_critical_servers
    n_emitted = emit_critical_servers(filtered)
    if n_emitted:
        console.print(f"[dim]CobaltoHQ: {n_emitted} high-risk events emitted[/dim]")


# ---------------------------------------------------------------------------
# feed-corvus
# ---------------------------------------------------------------------------

@app.command(name="feed-corvus")
def feed_corvus(
    results: Annotated[Path, typer.Argument(help="Petrel results.jsonl file")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output YAML (default: stdout)")] = None,
    min_risk: Annotated[str, typer.Option("--min-risk", help="Minimum risk tier to include")] = "INFO",
    source: Annotated[Optional[str], typer.Option("--source", "-s",
        help="Filter by discovery source: crtsh|huggingface|github|npm|smithery|pypi|censys|fofa"
    )] = None,
) -> None:
    """Convert Petrel results.jsonl → Corvus batch targets YAML."""
    import yaml  # type: ignore[import]

    if not results.exists():
        err.print(f"[red]File not found: {results}[/red]")
        raise typer.Exit(1)

    tier_order = [t.value for t in RiskTier]
    try:
        min_idx = tier_order.index(min_risk.upper())
    except ValueError:
        err.print(f"[red]Invalid --min-risk: {min_risk}. Choose from: {', '.join(tier_order)}[/red]")
        raise typer.Exit(1)

    original_records: list[dict] = []
    for line in results.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        original_records.append(r)

    all_records = [
        r for r in original_records
        if tier_order.index(r.get("risk_tier", "INFO")) <= min_idx
    ]

    # C4: --source filter
    if source:
        filtered_by_source = [r for r in all_records if r.get("discovered_via") == source]
        if not filtered_by_source:
            available = sorted({r.get("discovered_via", "?") for r in original_records})
            console.print(f"[yellow]No records from '{source}'. Available: {available}[/yellow]")
            raise typer.Exit(0)
        all_records = filtered_by_source

    if not all_records:
        console.print(f"[yellow]No records matching --min-risk {min_risk}[/yellow]")
        raise typer.Exit(0)

    # Corvus batch only supports streamable-http — SSE legacy is skipped
    records = [r for r in all_records if r.get("protocol") == "streamable-http"]
    skipped = len(all_records) - len(records)
    if skipped:
        console.print(f"[dim]Skipped {skipped} SSE-legacy servers (corvus doesn't support SSE transport)[/dim]")

    targets = []
    for r in records:
        # C4: use endpoint_path if available instead of always appending /mcp
        endpoint_path = r.get("endpoint_path") or "/mcp"
        effective_url = (r.get("final_url") or r["url"]).rstrip("/")
        target_url = f"{effective_url}{endpoint_path}"

        name = (r.get("final_url") or r["url"]).removeprefix("https://").removeprefix("http://").replace(".", "-").replace(":", "-")[:48]
        entry: dict = {"name": name, "transport": "http", "url": target_url}
        tags = [f"petrel-{r.get('risk_tier', 'INFO').lower()}"]
        if r.get("auth_state") == "none":
            tags.append("no-auth")
        entry["tags"] = tags
        entry["risk_tier"] = r.get("risk_tier", "INFO")
        targets.append(entry)

    _TIER_VALUES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    targets.sort(key=lambda e: _TIER_VALUES.index(e.get("risk_tier", "INFO")))
    doc = {"targets": targets}
    yaml_str = yaml.dump(doc, default_flow_style=False, allow_unicode=True, sort_keys=False)

    if output:
        output.write_text(yaml_str)
        console.print(f"[green]✓[/green] {len(targets)} targets → {output}")
        for r in records:
            tier_color = _TIER_COLOR.get(RiskTier(r["risk_tier"]), "white")
            console.print(f"  [{tier_color}]{r['risk_tier']}[/{tier_color}] {r.get('final_url') or r['url']}")
    else:
        console.print(yaml_str)


# ---------------------------------------------------------------------------
# stats  (C3)
# ---------------------------------------------------------------------------

@app.command()
def stats(
    results: Annotated[Path, typer.Argument(help="Petrel JSONL results file")],
) -> None:
    """Show statistics for a Petrel results file."""
    if not results.exists():
        err.print(f"[red]File not found: {results}[/red]")
        raise typer.Exit(1)

    records: list[dict] = []
    for line in results.read_text().splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))

    if not records:
        console.print("[yellow]No records found.[/yellow]")
        raise typer.Exit(0)

    console.print(_BANNER)
    console.print(f"[bold]Total records:[/bold] {len(records)}\n")

    def _breakdown_table(title: str, counter: Counter) -> None:
        t = Table(title=title, show_lines=False)
        t.add_column("Value", style="bold")
        t.add_column("Count", justify="right")
        t.add_column("Pct", justify="right")
        total = sum(counter.values())
        for key, count in counter.most_common():
            pct = f"{count / total * 100:.1f}%"
            t.add_row(str(key), str(count), pct)
        console.print(t)
        console.print()

    _breakdown_table(
        "Risk Tier Distribution",
        Counter(r.get("risk_tier", "?") for r in records),
    )
    _breakdown_table(
        "Protocol Breakdown",
        Counter(r.get("protocol", "?") for r in records),
    )
    _breakdown_table(
        "Auth State Breakdown",
        Counter(r.get("auth_state", "?") for r in records),
    )
    _breakdown_table(
        "Platform Breakdown",
        Counter(r.get("platform", "?") for r in records),
    )
    _breakdown_table(
        "Discovery Source Breakdown",
        Counter(r.get("discovered_via", "?") for r in records),
    )

    # Top 10 tool names
    tool_counter: Counter = Counter()
    for r in records:
        for tool in r.get("tools", []):
            name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
            if name:
                tool_counter[name] += 1

    if tool_counter:
        t = Table(title="Top 10 Tool Names", show_lines=False)
        t.add_column("Tool Name", style="bold")
        t.add_column("Count", justify="right")
        for name, count in tool_counter.most_common(10):
            t.add_row(name, str(count))
        console.print(t)


# ---------------------------------------------------------------------------
# diff  (C10)
# ---------------------------------------------------------------------------

@app.command()
def diff(
    old: Annotated[Path, typer.Argument(help="Previous results JSONL")],
    new: Annotated[Path, typer.Argument(help="Current results JSONL")],
    min_risk: Annotated[str, typer.Option("--min-risk")] = "MEDIUM",
) -> None:
    """Compare two Petrel results files — show new servers and risk changes."""
    for p in (old, new):
        if not p.exists():
            err.print(f"[red]File not found: {p}[/red]")
            raise typer.Exit(1)

    def _load(path: Path) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                r = json.loads(line)
                out[r["url"]] = r
        return out

    old_map = _load(old)
    new_map = _load(new)

    min_risk_upper = min_risk.upper()
    min_idx = _TIER_ORDER.index(RiskTier(min_risk_upper)) if min_risk_upper in RiskTier._value2member_map_ else len(_TIER_ORDER) - 1

    # New servers (in new but not in old)
    new_servers = {
        url: r for url, r in new_map.items()
        if url not in old_map
        and _TIER_ORDER.index(RiskTier(r.get("risk_tier", "INFO"))) <= min_idx
    }

    # Escalated (same URL, higher risk in new)
    escalated: dict[str, tuple[str, str]] = {}
    for url, new_r in new_map.items():
        if url in old_map:
            old_tier = RiskTier(old_map[url].get("risk_tier", "INFO"))
            new_tier = RiskTier(new_r.get("risk_tier", "INFO"))
            if _TIER_ORDER.index(new_tier) < _TIER_ORDER.index(old_tier):
                escalated[url] = (old_tier.value, new_tier.value)

    # Resolved (same URL, lower risk in new)
    resolved: dict[str, tuple[str, str]] = {}
    for url, old_r in old_map.items():
        if url in new_map:
            old_tier = RiskTier(old_r.get("risk_tier", "INFO"))
            new_tier = RiskTier(new_map[url].get("risk_tier", "INFO"))
            if _TIER_ORDER.index(new_tier) > _TIER_ORDER.index(old_tier):
                resolved[url] = (old_tier.value, new_tier.value)

    console.print(f"\n[bold]Diff:[/bold] {old.name} → {new.name}\n")

    if new_servers:
        t = Table(title=f"New Servers ({len(new_servers)})", show_lines=False)
        t.add_column("Risk", width=10)
        t.add_column("URL")
        t.add_column("Source")
        for url, r in sorted(new_servers.items(), key=lambda kv: _TIER_ORDER.index(RiskTier(kv[1].get("risk_tier", "INFO")))):
            tier = r.get("risk_tier", "INFO")
            color = _TIER_COLOR.get(RiskTier(tier), "white")
            t.add_row(f"[{color}]{tier}[/{color}]", url, r.get("discovered_via", "?"))
        console.print(t)
        console.print()

    if escalated:
        t = Table(title=f"Escalated Risk ({len(escalated)})", show_lines=False)
        t.add_column("URL")
        t.add_column("Old Risk")
        t.add_column("New Risk")
        for url, (old_t, new_t) in escalated.items():
            old_c = _TIER_COLOR.get(RiskTier(old_t), "white")
            new_c = _TIER_COLOR.get(RiskTier(new_t), "white")
            t.add_row(url, f"[{old_c}]{old_t}[/{old_c}]", f"[{new_c}]{new_t}[/{new_c}]")
        console.print(t)
        console.print()

    if resolved:
        t = Table(title=f"Resolved ({len(resolved)})", show_lines=False)
        t.add_column("URL")
        t.add_column("Old Risk")
        t.add_column("New Risk")
        for url, (old_t, new_t) in resolved.items():
            old_c = _TIER_COLOR.get(RiskTier(old_t), "white")
            new_c = _TIER_COLOR.get(RiskTier(new_t), "white")
            t.add_row(url, f"[{old_c}]{old_t}[/{old_c}]", f"[{new_c}]{new_t}[/{new_c}]")
        console.print(t)
        console.print()

    if not new_servers and not escalated and not resolved:
        console.print("[green]No changes above --min-risk threshold.[/green]")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _print_server(r: MCPServerRecord) -> None:
    color = _TIER_COLOR.get(r.risk_tier, "white")
    console.print(f"\n[{color}][{r.risk_tier}][/{color}] {r.url}")
    console.print(f"  Protocol : {r.protocol}")
    console.print(f"  Auth     : {r.auth_state}")
    if r.server_name:
        console.print(f"  Server   : {r.server_name} {r.server_version or ''}")
    if r.protocol_version:
        console.print(f"  Proto ver: {r.protocol_version}")
    if r.behind_cloudflare:
        console.print("  [dim]Behind Cloudflare[/dim]")
    if r.tools:
        console.print(f"  Tools ({len(r.tools)}):")
        for tool in r.tools:
            tc = _TIER_COLOR.get(tool.risk_tier, "dim")
            console.print(f"    [{tc}]• {tool.name}[/{tc}]")
    if r.risk_reasons:
        console.print(f"  Findings : {', '.join(r.risk_reasons)}")


def _print_summary(records: list[MCPServerRecord]) -> None:
    counts: Counter[RiskTier] = Counter(r.risk_tier for r in records)

    t = Table(title=f"Petrel — {len(records)} MCP servers confirmed", show_lines=False)
    t.add_column("Risk", style="bold", width=10)
    t.add_column("Count", justify="right", width=6)
    t.add_column("Servers")

    for tier in RiskTier:
        tier_records = [r for r in records if r.risk_tier == tier]
        if not tier_records:
            continue
        color = _TIER_COLOR[tier]
        preview = "  ".join(r.url for r in tier_records[:3])
        if len(tier_records) > 3:
            preview += f"  [dim]+{len(tier_records) - 3} more[/dim]"
        t.add_row(f"[{color}]{tier.value}[/{color}]", str(counts[tier]), preview)

    console.print()
    console.print(t)

    critical = [r for r in records if r.risk_tier == RiskTier.CRITICAL]
    if critical:
        console.print(f"\n[red bold]!  {len(critical)} CRITICAL — unauthenticated dangerous tool access:[/red bold]")
        for r in critical[:10]:
            console.print(f"  [red]→[/red] {r.url}  [dim]{', '.join(r.risk_reasons[:2])}[/dim]")


def _version_callback(value: bool) -> None:
    if value:
        print(f"petrel {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(None, "--version", "-V", callback=_version_callback, is_eager=True),
) -> None:
    pass
