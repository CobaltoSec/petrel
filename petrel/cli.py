"""Petrel CLI — MCP Internet Scanner & Fingerprinter."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .discovery.censys import censys_search
from .discovery.passive import crtsh_search, hf_spaces_search
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


@app.command()
def probe(
    url: Annotated[str, typer.Argument(help="URL to fingerprint")],
    json_out: Annotated[bool, typer.Option("--json", "-j", help="JSON output")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save results to file")] = None,
) -> None:
    """Fingerprint a single MCP server URL."""
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
    _print_server(result)

    data = result.model_dump(mode="json")
    if output:
        output.write_text(json.dumps(data, indent=2, default=str))
        console.print(f"\n[dim]Saved to {output}[/dim]")
    elif json_out:
        console.print_json(json.dumps(data, default=str))


@app.command()
def discover(
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save results (JSONL)")] = None,
    no_probe: Annotated[bool, typer.Option("--no-probe", help="Skip fingerprinting, list URLs only")] = False,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c")] = 20,
    no_censys: Annotated[bool, typer.Option("--no-censys", help="Skip Censys even if credentials are set")] = False,
) -> None:
    """Discover exposed MCP servers via passive sources (crt.sh + HuggingFace + Censys)."""
    console.print(_BANNER)

    async def _run() -> list[MCPServerRecord]:
        import httpx

        urls: list[str] = []

        with console.status("[cyan]Querying crt.sh (4 keywords)..."):
            crt_domains = await crtsh_search()
            crt_urls = [f"https://{d}" for d in crt_domains]
            urls.extend(crt_urls)
        console.print(f"  [green]crt.sh[/green]: {len(crt_domains)} domains")

        with console.status("[cyan]Querying HuggingFace Spaces (4 queries, paginated)..."):
            hf_urls = await hf_spaces_search()
            urls.extend(hf_urls)
        console.print(f"  [green]HuggingFace[/green]: {len(hf_urls)} spaces")

        if not no_censys:
            import os
            has_creds = bool(os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET"))
            if has_creds:
                with console.status("[cyan]Querying Censys..."):
                    censys_urls = await censys_search()
                urls.extend(censys_urls)
                console.print(f"  [green]Censys[/green]: {len(censys_urls)} hosts")
            else:
                console.print("  [dim]Censys: skipped (no CENSYS_API_ID/CENSYS_API_SECRET)[/dim]")

        # Deduplicate preserving first-seen order
        urls = list(dict.fromkeys(urls))
        console.print(f"\n[bold]Candidates:[/bold] {len(urls)}")

        if no_probe:
            for u in urls:
                console.print(f"  {u}")
            return []

        console.print("[cyan]Fingerprinting...[/cyan]")
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            raw = await probe_urls_batch(urls, client, concurrency=concurrency)

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


@app.command()
def scan(
    targets: Annotated[Path, typer.Argument(help="File with URLs, one per line")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c")] = 20,
    min_risk: Annotated[str, typer.Option("--min-risk")] = "INFO",
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

    tier_order = list(RiskTier)
    min_idx = tier_order.index(RiskTier(min_risk.upper())) if min_risk.upper() in RiskTier._value2member_map_ else len(tier_order)
    filtered = [r for r in records if tier_order.index(r.risk_tier) <= min_idx]

    _print_summary(filtered)

    if output and filtered:
        with output.open("w") as f:
            for r in filtered:
                f.write(json.dumps(r.model_dump(mode="json"), default=str) + "\n")
        console.print(f"\n[dim]Saved to {output}[/dim]")


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
    from collections import Counter

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
        console.print(f"\n[red bold]⚠  {len(critical)} CRITICAL — unauthenticated dangerous tool access:[/red bold]")
        for r in critical[:10]:
            console.print(f"  [red]→[/red] {r.url}  [dim]{', '.join(r.risk_reasons[:2])}[/dim]")


@app.command(name="feed-corvus")
def feed_corvus(
    results: Annotated[Path, typer.Argument(help="Petrel results.jsonl file")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output YAML (default: stdout)")] = None,
    min_risk: Annotated[str, typer.Option("--min-risk", help="Minimum risk tier to include")] = "INFO",
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

    records: list[dict] = []
    for line in results.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if tier_order.index(r.get("risk_tier", "INFO")) <= min_idx:
            records.append(r)

    if not records:
        console.print(f"[yellow]No records matching --min-risk {min_risk}[/yellow]")
        raise typer.Exit(0)

    targets = []
    for r in records:
        # Pass base URL — corvus auto-detects the correct endpoint path
        url = r["url"].rstrip("/")

        name = url.removeprefix("https://").removeprefix("http://").replace(".", "-").replace(":", "-")[:48]
        entry: dict = {"name": name, "transport": "http", "url": url}
        if r.get("risk_tier") in ("CRITICAL", "HIGH"):
            entry["tags"] = [f"petrel-{r['risk_tier'].lower()}", "no-auth"]
        targets.append(entry)

    doc = {"targets": targets}
    yaml_str = yaml.dump(doc, default_flow_style=False, allow_unicode=True, sort_keys=False)

    if output:
        output.write_text(yaml_str)
        console.print(f"[green]✓[/green] {len(targets)} targets → {output}")
        for r in records:
            tier_color = _TIER_COLOR.get(RiskTier(r["risk_tier"]), "white")
            console.print(f"  [{tier_color}]{r['risk_tier']}[/{tier_color}] {r['url']}")
    else:
        console.print(yaml_str)


def _version_callback(value: bool) -> None:
    if value:
        print(f"petrel {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(None, "--version", "-V", callback=_version_callback, is_eager=True),
) -> None:
    pass
