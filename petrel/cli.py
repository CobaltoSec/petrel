"""Petrel CLI — MCP Internet Scanner & Fingerprinter."""
from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated, Any, Optional
from urllib.parse import urlparse, urlunparse

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TimeRemainingColumn
from rich.table import Table

from . import __version__
from .discovery.censys import censys_search
from .discovery.fofa import fofa_search
from .discovery.github import github_search
from .discovery.npm import npm_search
from .discovery.passive import crtsh_search, hf_spaces_search
from .discovery.pypi import pypi_search
from .discovery.registries import registries_search
from .discovery.shodan import shodan_search
from .discovery.smithery import smithery_search
from .fingerprint.probe import probe_url, probe_urls_batch
from .models import MCPServerRecord, RiskTier, SourceResult
from .scoring.risk import apply_persistence_bonus, score_server
from .store import create_run, finish_run, get_consecutive_runs_map, update_server_history
from .summary import generate_run_summary

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
# helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Normalize a URL for deduplication: lowercase host, strip trailing slash, strip default ports."""
    try:
        p = urlparse(url.rstrip("/"))
        host = p.hostname or ""
        port = p.port
        if (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80):
            port = None
        netloc = host if port is None else f"{host}:{port}"
        return urlunparse((p.scheme, netloc, p.path.rstrip("/"), p.params, p.query, ""))
    except Exception:
        return url


async def _gather_sources(
    no_censys: bool,
    no_github: bool,
    no_npm: bool,
    no_smithery: bool,
    no_pypi: bool,
    no_fofa: bool,
    no_shodan: bool = False,
    no_registries: bool = False,
) -> list[tuple[str, str]]:
    """Run all enabled discovery sources in parallel. Returns [(url, source_name), ...]."""
    import os

    tasks: list[tuple[str, Any]] = []
    skipped_msgs: list[str] = []
    smithery_key: str | None = None

    # Always include crtsh and huggingface
    tasks.append(("crtsh", crtsh_search()))
    tasks.append(("huggingface", hf_spaces_search()))

    if not no_censys:
        if os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET"):
            tasks.append(("censys", censys_search()))
        else:
            skipped_msgs.append("  [dim]Censys: skipped (no CENSYS_API_ID/CENSYS_API_SECRET)[/dim]")

    if not no_github:
        tasks.append(("github", github_search()))

    if not no_npm:
        tasks.append(("npm", npm_search()))

    if not no_smithery:
        smithery_key = os.getenv("SMITHERY_API_KEY")
        tasks.append(("smithery", smithery_search(api_key=smithery_key)))

    if not no_pypi:
        tasks.append(("pypi", pypi_search()))

    if not no_fofa:
        if os.getenv("FOFA_EMAIL") and os.getenv("FOFA_KEY"):
            tasks.append(("fofa", fofa_search()))
        else:
            skipped_msgs.append("  [dim]FOFA: skipped (no FOFA_EMAIL/FOFA_KEY)[/dim]")

    if os.environ.get("SHODAN_API_KEY") and not no_shodan:
        tasks.append(("shodan", shodan_search()))
    elif not no_shodan:
        skipped_msgs.append("  [dim]Shodan: skipped (no SHODAN_API_KEY)[/dim]")

    if not no_registries:
        tasks.append(("registries", registries_search()))

    # Run all in parallel
    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    # Print skipped messages
    for msg in skipped_msgs:
        console.print(msg)

    _label_map = {
        "crtsh": "crt.sh",
        "huggingface": "HuggingFace",
        "github": "GitHub",
        "npm": "npm",
        "smithery": "Smithery",
        "pypi": "PyPI",
        "censys": "Censys",
        "fofa": "FOFA",
        "shodan": "Shodan",
        "registries": "Registries",
    }

    url_sources: list[tuple[str, str]] = []
    for (src_name, _), result in zip(tasks, results):
        label = _label_map.get(src_name, src_name)

        if isinstance(result, Exception):
            console.print(f"  [yellow]{label}: EXCEPTION — {result}[/yellow]")
            continue

        # result is a SourceResult (list subclass)
        sr: SourceResult = result  # type: ignore[assignment]

        if sr.error:
            console.print(f"  [yellow]{label}: ERROR — {sr.error}[/yellow]")
            # still use any partial results

        # Convert to full URLs
        if src_name == "crtsh":
            src_urls = [f"https://{d}" for d in sr.urls]
        else:
            src_urls = sr.urls

        if not sr.error:
            if sr.warnings:
                console.print(
                    f"  [green]{label}[/green]: {len(sr.urls)} candidates "
                    f"[yellow]({'; '.join(sr.warnings)})[/yellow]"
                )
            elif src_name == "crtsh":
                console.print(f"  [green]{label}[/green]: {len(sr.urls)} domains")
            elif src_name == "smithery":
                if smithery_key:
                    console.print(f"  [green]{label}[/green]: {len(sr.urls)} servers")
                else:
                    console.print(
                        f"  [dim]{label}[/dim]: {len(sr.urls)} servers "
                        f"[dim](set SMITHERY_API_KEY for full access ~6,756)[/dim]"
                    )
            elif src_name in ("github", "npm", "pypi"):
                console.print(f"  [green]{label}[/green]: {len(sr.urls)} packages with deployment URLs")
            else:
                console.print(f"  [green]{label}[/green]: {len(sr.urls)} hosts")

        url_sources.extend((u, src_name) for u in src_urls)

    return url_sources


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

    try:
        from petrel.output.cobaltohq import emit_critical_servers
        emit_critical_servers([result])
    except Exception:
        pass

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
    no_shodan: Annotated[bool, typer.Option("--no-shodan", help="Skip Shodan search")] = False,
    no_registries: Annotated[bool, typer.Option("--no-registries", help="Skip Registries search")] = False,
    resume: Annotated[Optional[Path], typer.Option("--resume", help="JSONL with already-confirmed URLs to skip")] = None,
    since: Annotated[Optional[Path], typer.Option("--since", help="Previous results JSONL — skip already-discovered candidates")] = None,
    sarif_out: Annotated[Optional[Path], typer.Option("--sarif", help="Save SARIF 2.1.0 report")] = None,
    html_out: Annotated[Optional[Path], typer.Option("--html", help="Save HTML report")] = None,
    markdown_out: Annotated[Optional[Path], typer.Option("--markdown", help="Save Markdown table")] = None,
    csv_out: Annotated[Optional[Path], typer.Option("--csv", help="Save CSV")] = None,
) -> None:
    """Discover exposed MCP servers via passive sources (crt.sh + HuggingFace + Censys + GitHub + npm + Smithery + PyPI + FOFA)."""
    console.print(_BANNER)

    run_id = create_run(label=str(output) if output else None, source="discover", jsonl_path=str(output) if output else None)

    async def _run() -> tuple[list[MCPServerRecord], int]:
        import httpx

        # PERF-02: Run all discovery sources in parallel
        console.print("[cyan]Querying discovery sources (parallel)...[/cyan]")
        url_sources = await _gather_sources(
            no_censys=no_censys, no_github=no_github, no_npm=no_npm,
            no_smithery=no_smithery, no_pypi=no_pypi, no_fofa=no_fofa,
            no_shodan=no_shodan, no_registries=no_registries,
        )

        # DISC-002: normalize + dedup
        source_map: dict[str, str] = {}
        for url, src in url_sources:
            norm = _normalize_url(url)
            if norm not in source_map:
                source_map[norm] = src
        urls = list(source_map.keys())

        # C6: --since deduplication
        if since and since.exists():
            prev_urls: set[str] = set()
            for line in since.read_text().splitlines():
                line = line.strip()
                if line:
                    r = json.loads(line)
                    prev_urls.add(_normalize_url(r["url"]))
                    if r.get("final_url"):
                        prev_urls.add(_normalize_url(r["final_url"]))
            before = len(urls)
            urls = [u for u in urls if u not in prev_urls]
            console.print(f"[dim]--since: {before - len(urls)} already known, {len(urls)} new candidates[/dim]")

        # C5: --resume (skip already-confirmed)
        if resume and resume.exists():
            seen_urls = {
                _normalize_url(json.loads(line)["url"])
                for line in resume.read_text().splitlines()
                if line.strip()
            }
            before = len(urls)
            urls = [u for u in urls if u not in seen_urls]
            console.print(f"[dim]Resume: skipping {len(seen_urls)} already-confirmed, {len(urls)} remaining[/dim]")

        candidate_count = len(urls)
        console.print(f"\n[bold]Candidates:[/bold] {candidate_count}")

        # C2: --no-probe saves URL list to file
        if no_probe:
            if output:
                output.write_text("\n".join(urls))
                console.print(f"[dim]{candidate_count} candidates saved to {output}[/dim]")
            else:
                for u in urls:
                    console.print(f"  {u}")
            return [], candidate_count

        # Persistence scoring: pre-load consecutive_confirmed_runs from history
        # (uses data from previous runs; this run's data is written AFTER probing)
        _history_map: dict[str, int] = get_consecutive_runs_map(urls)

        # PERF-01: open output file early for incremental writing
        _out_fh = output.open("w", encoding="utf-8") if output else None
        confirmed_for_summary: list[MCPServerRecord] = []
        raw: list = []

        try:
            # PERF-07: progress bar on stderr
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=err,
            ) as progress:
                task = progress.add_task("[cyan]Fingerprinting...", total=candidate_count)

                def _on_result(r: MCPServerRecord) -> None:
                    """Called for each confirmed MCP server (PERF-01 + PERF-07)."""
                    if r.is_confirmed_mcp:
                        scored = score_server(r)
                        # Apply persistence bonus based on prior confirmed runs
                        _ccr = _history_map.get(r.url, 0)
                        if _ccr > 1:
                            scored = apply_persistence_bonus(scored, _ccr)
                        confirmed_for_summary.append(scored)
                        if _out_fh is not None:
                            _out_fh.write(json.dumps(scored.model_dump(mode="json"), default=str) + "\n")
                            _out_fh.flush()
                        progress.advance(task, 1)

                async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                    raw = await probe_urls_batch(
                        urls, client,
                        concurrency=concurrency,
                        source_map=source_map,
                        on_result=_on_result,
                    )
        finally:
            if _out_fh is not None:
                _out_fh.close()

        # F-07: probe failure count
        failure_count = sum(
            1 for r in raw
            if r is None or (hasattr(r, "is_confirmed_mcp") and not r.is_confirmed_mcp)
        )
        if failure_count:
            console.print(f"[dim]Probe failures: {failure_count} (down/non-MCP/timeout)[/dim]")

        # If no output file, build confirmed list from raw
        if not output:
            confirmed_for_summary = []
            for r in raw:
                if r is not None and r.is_confirmed_mcp:
                    scored = score_server(r)
                    _ccr = _history_map.get(r.url, 0)
                    if _ccr > 1:
                        scored = apply_persistence_bonus(scored, _ccr)
                    confirmed_for_summary.append(scored)

        return confirmed_for_summary, candidate_count

    records, candidate_count = asyncio.run(_run())

    if records:
        _print_summary(records)

    finish_run(run_id, records)

    # Decay model: track server lifespan across runs
    _decay = update_server_history(run_id, [r.url for r in records])
    console.print(
        f"[dim]Decay model: {_decay['new']} nuevos, {_decay['decayed']} caidos "
        f"(total activos: {_decay['total_active']})[/dim]"
    )

    # Post-run funnel summary
    _summary_path = generate_run_summary(run_id, records, _decay, candidate_count=candidate_count)
    console.print(f"[dim]Run summary: {_summary_path}[/dim]")

    if output and records:
        console.print(f"\n[dim]Results saved incrementally to {output}[/dim]")

    # C8: SARIF + HTML output
    if sarif_out and records:
        from .output.sarif import write_sarif
        write_sarif(records, sarif_out)
        console.print(f"[dim]SARIF saved to {sarif_out}[/dim]")
    if html_out and records:
        from .output.html import write_html
        write_html(records, html_out)
        console.print(f"[dim]HTML report saved to {html_out}[/dim]")
    if markdown_out and records:
        from .output.markdown import write_markdown
        write_markdown(records, markdown_out)
        console.print(f"[dim]Markdown saved to {markdown_out}[/dim]")
    if csv_out and records:
        from .output.csv import write_csv
        write_csv(records, csv_out)
        console.print(f"[dim]CSV saved to {csv_out}[/dim]")

    # Always emit critical events to CobaltoHQ
    from .output.cobaltohq import emit_critical_servers, emit_scan_completed
    n_emitted = emit_critical_servers(records)
    if n_emitted:
        console.print(f"[dim]CobaltoHQ: {n_emitted} high-risk events emitted[/dim]")
    emit_scan_completed(records, command="discover", output_file=str(output) if output else None)


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
    markdown_out: Annotated[Optional[Path], typer.Option("--markdown", help="Save Markdown table")] = None,
    csv_out: Annotated[Optional[Path], typer.Option("--csv", help="Save CSV")] = None,
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
        _out_fh = output.open("w", encoding="utf-8") if output else None
        confirmed: list[MCPServerRecord] = []
        raw: list = []

        try:
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=err,
            ) as progress:
                task = progress.add_task("[cyan]Fingerprinting...", total=len(urls))

                def _on_result(r: MCPServerRecord) -> None:
                    if r.is_confirmed_mcp:
                        scored = score_server(r)
                        confirmed.append(scored)
                        if _out_fh is not None:
                            _out_fh.write(json.dumps(scored.model_dump(mode="json"), default=str) + "\n")
                            _out_fh.flush()
                        progress.advance(task, 1)

                async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                    raw = await probe_urls_batch(
                        urls, client,
                        concurrency=concurrency,
                        on_result=_on_result,
                    )
        finally:
            if _out_fh is not None:
                _out_fh.close()

        # F-07: probe failure count
        failure_count = sum(
            1 for r in raw
            if r is None or (hasattr(r, "is_confirmed_mcp") and not r.is_confirmed_mcp)
        )
        if failure_count:
            console.print(f"[dim]Probe failures: {failure_count} (down/non-MCP/timeout)[/dim]")

        if not output:
            confirmed = [score_server(r) for r in raw if r is not None and r.is_confirmed_mcp]

        return confirmed

    records = asyncio.run(_run())

    min_risk_upper = min_risk.upper()
    if min_risk_upper in RiskTier._value2member_map_:
        min_idx = _TIER_ORDER.index(RiskTier(min_risk_upper))
        filtered = [r for r in records if _TIER_ORDER.index(r.risk_tier) <= min_idx]
    else:
        filtered = records

    _print_summary(filtered)

    if output and filtered:
        console.print(f"\n[dim]Saved incrementally to {output}[/dim]")

    # C8: SARIF + HTML
    if sarif_out and filtered:
        from .output.sarif import write_sarif
        write_sarif(filtered, sarif_out)
        console.print(f"[dim]SARIF saved to {sarif_out}[/dim]")
    if html_out and filtered:
        from .output.html import write_html
        write_html(filtered, html_out)
        console.print(f"[dim]HTML report saved to {html_out}[/dim]")
    if markdown_out and filtered:
        from .output.markdown import write_markdown
        write_markdown(filtered, markdown_out)
        console.print(f"[dim]Markdown saved to {markdown_out}[/dim]")
    if csv_out and filtered:
        from .output.csv import write_csv
        write_csv(filtered, csv_out)
        console.print(f"[dim]CSV saved to {csv_out}[/dim]")

    # Always emit critical events to CobaltoHQ
    from .output.cobaltohq import emit_critical_servers, emit_scan_completed
    n_emitted = emit_critical_servers(filtered)
    if n_emitted:
        console.print(f"[dim]CobaltoHQ: {n_emitted} high-risk events emitted[/dim]")
    emit_scan_completed(filtered, command="scan", targets_count=len(urls), output_file=str(output) if output else None)


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
    include_waf: Annotated[bool, typer.Option("--include-waf", help="Include CDN/WAF-protected servers (behind_cloudflare=true)")] = False,
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

    # WAF/CDN filter — skip Cloudflare-protected servers unless --include-waf
    if not include_waf:
        waf_filtered = [r for r in records if not r.get("behind_cloudflare", False)]
        waf_skipped = len(records) - len(waf_filtered)
        if waf_skipped:
            console.print(f"[dim]Skipped {waf_skipped} CDN/WAF-protected servers (use --include-waf to include)[/dim]")
        records = waf_filtered

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
        entry["priority_score"] = r.get("priority_score", 0)
        targets.append(entry)

    _TIER_VALUES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    targets.sort(key=lambda e: (_TIER_VALUES.index(e.get("risk_tier", "INFO")), -e.get("priority_score", 0)))
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
# runs / runs-diff
# ---------------------------------------------------------------------------

@app.command(name="runs")
def runs_list() -> None:
    """List saved scan runs."""
    from petrel.storage import list_runs

    rows = list_runs()
    if not rows:
        typer.echo("No runs saved.")
        return
    for r in rows:
        tag = f" [{r['tag']}]" if r["tag"] else ""
        typer.echo(f"{r['id']}{tag}  {r['ts'][:19]}  {r['count']} servers")


@app.command(name="runs-diff")
def runs_diff(tag1: str, tag2: str) -> None:
    """Diff two scan runs by tag or ID."""
    from petrel.storage import diff_runs

    only1, only2 = diff_runs(tag1, tag2)
    if only1:
        typer.echo(f"Only in {tag1} ({len(only1)}):")
        for u in sorted(only1):
            typer.echo(f"  - {u}")
    if only2:
        typer.echo(f"Only in {tag2} ({len(only2)}):")
        for u in sorted(only2):
            typer.echo(f"  + {u}")
    if not only1 and not only2:
        typer.echo("No differences.")


# ---------------------------------------------------------------------------
# feed-condor
# ---------------------------------------------------------------------------

@app.command(name="feed-condor")
def feed_condor(
    results: Annotated[Path, typer.Argument(help="Petrel results.jsonl file")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output file (default: stdout)")] = None,
    min_score: Annotated[int, typer.Option(help="Minimum priority_score")] = 50,
) -> None:
    """Filter Petrel results for agentic platforms and generate Condor targets."""
    import json as _json

    _AGENTIC_KEYWORDS = ["flowise", "langflow", "dify", "n8n", "autogen", "langchain", "llamaflow"]

    if not results.exists():
        err.print(f"[red]File not found: {results}[/red]")
        raise typer.Exit(1)

    lines: list[str] = []
    for line in results.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = _json.loads(line)
        except Exception:
            continue
        score = rec.get("priority_score", 0)
        if score < min_score:
            continue
        name = (rec.get("server_name") or rec.get("url", "")).lower()
        matched = next((k for k in _AGENTIC_KEYWORDS if k in name), None)
        if not matched:
            continue
        platform = matched if matched in ("flowise", "langflow", "dify", "autogen") else "generic"
        url = rec.get("url", "")
        lines.append(f"{url} {platform}")

    content = "\n".join(lines) + "\n" if lines else ""
    if output:
        output.write_text(content)
        typer.echo(f"Wrote {len(lines)} targets to {output}")
    else:
        typer.echo(content, nl=False)


# ---------------------------------------------------------------------------
# feed-shrike
# ---------------------------------------------------------------------------

@app.command(name="feed-shrike")
def feed_shrike(
    results: Annotated[Path, typer.Argument(help="Petrel results.jsonl file")],
    output: Annotated[Optional[Path], typer.Option(
        "--output", "-o",
        help="Output YAML (default: C:/Proyectos/Shrike/state/targets/petrel-criticals.yaml)",
    )] = None,
    filter_source: Annotated[str, typer.Option(
        "--filter-source", "-s",
        help="Filter by discovery source (e.g. github, crtsh, npm, smithery)",
    )] = "github",
    min_priority: Annotated[int, typer.Option(
        "--min-priority",
        help="Minimum priority_score to include (also includes auth=none AND high/critical regardless)",
    )] = 50,
) -> None:
    """Convert Petrel results.jsonl → Shrike targets YAML (github-sourced by default)."""
    import yaml  # type: ignore[import]
    from datetime import date as _date

    _DEFAULT_OUTPUT = Path("C:/Proyectos/Shrike/state/targets/petrel-criticals.yaml")

    if not results.exists():
        err.print(f"[red]File not found: {results}[/red]")
        raise typer.Exit(1)

    original_records: list[dict] = []
    for line in results.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        original_records.append(r)

    if not original_records:
        console.print("[yellow]No records found in input file.[/yellow]")
        raise typer.Exit(0)

    # Filter by source
    if filter_source:
        by_source = [r for r in original_records if r.get("discovered_via") == filter_source]
        if not by_source:
            available = sorted({r.get("discovered_via", "?") for r in original_records})
            console.print(
                f"[yellow]No records with source '{filter_source}'. "
                f"Available sources: {available}[/yellow]"
            )
            raise typer.Exit(0)
    else:
        by_source = original_records

    # Filter by priority_score >= min_priority OR (auth=none AND CRITICAL/HIGH)
    filtered: list[dict] = []
    for r in by_source:
        score = r.get("priority_score", 0)
        auth = r.get("auth_state", "unknown")
        tier = r.get("risk_tier", "INFO")
        passes_score = score >= min_priority
        passes_auth_severity = auth == "none" and tier in ("CRITICAL", "HIGH")
        if passes_score or passes_auth_severity:
            filtered.append(r)

    if not filtered:
        console.print(
            f"[yellow]No servers passed filters "
            f"(source={filter_source!r}, min_priority={min_priority}). "
            f"Total in source: {len(by_source)}.[/yellow]"
        )
        raise typer.Exit(0)

    run_date = _date.today().isoformat()

    targets: list[dict] = []
    for r in filtered:
        entry = {
            "url": r.get("final_url") or r["url"],
            "source": "petrel",
            "priority_score": r.get("priority_score", 0),
            "auth": r.get("auth_state", "unknown"),
            "tools_count": len(r.get("tools", [])),
            "run_date": run_date,
        }
        targets.append(entry)

    # Sort by priority_score descending
    targets.sort(key=lambda e: -e["priority_score"])

    doc = {"targets": targets}
    yaml_str = yaml.dump(doc, default_flow_style=False, allow_unicode=True, sort_keys=False)

    out_path = output if output is not None else _DEFAULT_OUTPUT
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml_str, encoding="utf-8")

    console.print(f"[green]✓[/green] {len(targets)} servers exported → {out_path}")
    for entry in targets[:10]:
        auth_color = "red" if entry["auth"] == "none" else "dim"
        console.print(
            f"  [bold]{entry['priority_score']:3d}[/bold]  "
            f"[{auth_color}]{entry['auth']:10s}[/{auth_color}]  "
            f"{entry['url']}"
        )
    if len(targets) > 10:
        console.print(f"  [dim]... and {len(targets) - 10} more[/dim]")


# ---------------------------------------------------------------------------
# feed-ibis
# ---------------------------------------------------------------------------

# Exec-family tool names (subset of scoring/risk.py _FAMILY_CODE_EXEC)
_IBIS_EXEC_NAMES = frozenset([
    "execute_bash", "execute_command", "run_command", "run_script",
    "execute_script", "run_python", "execute_python", "python_repl",
    "code_exec", "subprocess_run", "system_exec", "bash", "shell",
])


def _has_exec_cluster(tools: list) -> bool:
    """Return True if any tool name matches exec-family keywords."""
    for t in tools:
        name = (t.get("name", "") if isinstance(t, dict) else getattr(t, "name", "")).lower()
        if name in _IBIS_EXEC_NAMES or any(p in name for p in _IBIS_EXEC_NAMES):
            return True
    return False


@app.command(name="feed-ibis")
def feed_ibis(
    results: Annotated[Path, typer.Argument(help="Petrel results.jsonl file")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview without creating ibis stubs")] = False,
    ibis_bin: Annotated[str, typer.Option("--ibis-bin", help="Path to ibis CLI binary")] = r"C:\Proyectos\Ibis\.venv\Scripts\ibis.exe",
) -> None:
    """Generate Ibis disclosure stubs for CRITICAL/HIGH MCP servers found by Petrel.

    Filters: risk_tier CRITICAL or HIGH, AND (auth=none OR exec-cluster tools).
    Creates a draft advisory in Ibis for each matching server (--dry-run for preview).
    """
    import subprocess
    from urllib.parse import urlparse as _urlparse

    if not results.exists():
        err.print(f"[red]File not found: {results}[/red]")
        raise typer.Exit(1)

    _HIGH_TIERS = {"CRITICAL", "HIGH"}

    records: list[dict] = []
    for line in results.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        records.append(r)

    # Filter: CRITICAL/HIGH AND (no-auth OR exec cluster)
    candidates: list[dict] = []
    for r in records:
        tier = r.get("risk_tier", "INFO")
        if tier not in _HIGH_TIERS:
            continue
        auth = r.get("auth_state", "unknown")
        tools = r.get("tools", [])
        if auth == "none" or _has_exec_cluster(tools):
            candidates.append(r)

    if not candidates:
        console.print("[yellow]No CRITICAL/HIGH servers with no-auth or exec cluster found.[/yellow]")
        raise typer.Exit(0)

    # Build output table
    table = Table(title=f"Ibis stubs {'(DRY RUN)' if dry_run else ''}", box=None)
    table.add_column("URL", style="cyan", no_wrap=True)
    table.add_column("Tier", style="bold")
    table.add_column("Auth")
    table.add_column("Package")
    table.add_column("Status")

    submitted: list[dict] = []

    for r in candidates:
        url = r.get("final_url") or r["url"]
        tier = r.get("risk_tier", "HIGH")
        auth = r.get("auth_state", "unknown")
        severity = tier.lower()

        # Derive package name from hostname
        parsed = _urlparse(url)
        hostname = parsed.hostname or url
        package = hostname.split(":")[0]  # strip port if present

        tier_color = _TIER_COLOR.get(RiskTier(tier), "white") if tier in RiskTier._value2member_map_ else "white"
        auth_color = "red" if auth == "none" else "dim"

        if dry_run:
            status = "[dim]dry-run[/dim]"
        else:
            try:
                proc = subprocess.run(
                    [ibis_bin, "add", "--package", package, "--severity", severity,
                     "--source", "manual", "--no-npm"],
                    capture_output=True, text=True, timeout=15,
                )
                if proc.returncode == 0:
                    # Extract generated GHSA ID from output (first MANUAL-* token)
                    import re as _re
                    m = _re.search(r"(MANUAL-[a-f0-9]+)", proc.stdout)
                    ghsa = m.group(1) if m else "?"
                    status = f"[green]✓ {ghsa}[/green]"
                    submitted.append({"url": url, "package": package, "severity": severity, "ghsa": ghsa})
                else:
                    status = f"[red]✗ {proc.stderr.strip()[:40]}[/red]"
            except FileNotFoundError:
                err.print(f"[red]ibis binary not found: {ibis_bin}[/red]")
                raise typer.Exit(1)
            except subprocess.TimeoutExpired:
                status = "[red]timeout[/red]"
            except Exception as exc:
                status = f"[red]error: {exc}[/red]"

        table.add_row(
            url[:60],
            f"[{tier_color}]{tier}[/{tier_color}]",
            f"[{auth_color}]{auth}[/{auth_color}]",
            package,
            status,
        )

    console.print(table)
    if not dry_run:
        console.print(f"\n[bold green]✓[/bold green] {len(submitted)}/{len(candidates)} stubs created in Ibis.")
    else:
        console.print(f"\n[dim]{len(candidates)} server(s) would be submitted to Ibis (--dry-run).[/dim]")


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

    # F-06: Cloudflare %, tool count distribution, schema completeness %
    console.print()
    cf_count = sum(1 for r in records if r.get("behind_cloudflare"))
    cf_pct = cf_count / len(records) * 100 if records else 0
    console.print(f"[bold]Behind Cloudflare:[/bold] {cf_count}/{len(records)} ({cf_pct:.1f}%)\n")

    tool_dist: Counter = Counter()
    for r in records:
        n = len(r.get("tools", []))
        if n == 0:
            bucket = "0"
        elif n <= 5:
            bucket = "1-5"
        elif n <= 20:
            bucket = "6-20"
        elif n <= 50:
            bucket = "21-50"
        else:
            bucket = "50+"
        tool_dist[bucket] += 1
    _breakdown_table("Tool Count Distribution", tool_dist)

    with_tools = [r for r in records if r.get("tools")]
    if with_tools:
        schema_complete = sum(
            1 for r in with_tools
            if any(t.get("inputSchema") for t in r.get("tools", []) if isinstance(t, dict))
        )
        schema_pct = schema_complete / len(with_tools) * 100
        console.print(
            f"[bold]Schema completeness:[/bold] {schema_complete}/{len(with_tools)} "
            f"servers with tools have inputSchema ({schema_pct:.1f}%)\n"
        )


# ---------------------------------------------------------------------------
# diff  (C10)
# ---------------------------------------------------------------------------

@app.command()
def diff(
    old: Annotated[Path, typer.Argument(help="Previous results JSONL")],
    new: Annotated[Path, typer.Argument(help="Current results JSONL")],
    min_risk: Annotated[str, typer.Option("--min-risk")] = "MEDIUM",
    classify: Annotated[bool, typer.Option("--classify", help="Probe disappeared servers to classify why they vanished")] = False,
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

    # F-03: Disappeared (in old but not in new)
    disappeared = {
        url: r for url, r in old_map.items()
        if url not in new_map
    }

    # --classify: probe disappeared servers to explain why they vanished
    if classify and disappeared:
        from .diff import classify_disappearances_batch

        console.print(f"[cyan]Classifying {len(disappeared)} disappeared server(s)...[/cyan]")
        groups = asyncio.run(classify_disappearances_batch(list(disappeared.values())))
        console.print(f"\nDisappeared servers ({len(disappeared)} total):")
        console.print(f"  [yellow]🔒 auth_added:  {len(groups['auth_added']):>3}[/yellow]  (likely hardened after our scan)")
        console.print(f"  [red]📴 taken_down:  {len(groups['taken_down']):>3}[/red]")
        console.print(f"  [blue]🔀 url_changed: {len(groups['url_changed']):>3}[/blue]")
        console.print(f"  [dim]❓ unknown:     {len(groups['unknown']):>3}[/dim]")
        console.print()

    # F-04: New tools in existing servers
    new_tools: dict[str, list[str]] = {}
    for url in set(old_map) & set(new_map):
        old_tool_names = {
            t.get("name") if isinstance(t, dict) else t
            for t in old_map[url].get("tools", [])
        }
        added = [
            t.get("name") if isinstance(t, dict) else t
            for t in new_map[url].get("tools", [])
            if (t.get("name") if isinstance(t, dict) else t) not in old_tool_names
        ]
        if added:
            new_tools[url] = added

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

    # F-03: Disappeared table
    if disappeared:
        t = Table(title=f"Disappeared ({len(disappeared)})", show_lines=False)
        t.add_column("Risk", width=10)
        t.add_column("URL")
        for url, r in sorted(
            disappeared.items(),
            key=lambda kv: _TIER_ORDER.index(RiskTier(kv[1].get("risk_tier", "INFO"))),
        ):
            tier = r.get("risk_tier", "INFO")
            color = _TIER_COLOR.get(RiskTier(tier), "white")
            t.add_row(f"[{color}]{tier}[/{color}]", url)
        console.print(t)
        console.print()

    # F-04: New tools in existing servers
    if new_tools:
        t = Table(title=f"New Tools in Existing Servers ({len(new_tools)} servers)", show_lines=False)
        t.add_column("URL")
        t.add_column("New Tools")
        for url, tools in new_tools.items():
            tool_preview = ", ".join(str(x) for x in tools[:5])
            if len(tools) > 5:
                tool_preview += f" +{len(tools) - 5} more"
            t.add_row(url, tool_preview)
        console.print(t)
        console.print()

    if not new_servers and not escalated and not resolved and not disappeared and not new_tools:
        console.print("[green]No changes above --min-risk threshold.[/green]")

    try:
        from .output.cobaltohq import emit_scan_completed as _emit  # type: ignore[import]
        from cobalt_hub_client import emit as _hub_emit  # type: ignore[import]
        new_critical = sum(1 for r in new_servers.values() if r.get("risk_tier") == "CRITICAL")
        new_high = sum(1 for r in new_servers.values() if r.get("risk_tier") == "HIGH")
        _hub_emit("petrel.diff.completed", {
            "old_file": old.name,
            "new_file": new.name,
            "new_servers": len(new_servers),
            "new_critical": new_critical,
            "new_high": new_high,
            "escalated": len(escalated),
            "resolved": len(resolved),
            "disappeared": len(disappeared),
        }, "petrel")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# report  (F-05)
# ---------------------------------------------------------------------------

@app.command()
def report(
    jsonl: Annotated[Path, typer.Argument(help="Petrel results JSONL file")],
    sarif: Annotated[bool, typer.Option("--sarif/--no-sarif", help="Generate SARIF 2.1.0 report")] = True,
    html: Annotated[bool, typer.Option("--html/--no-html", help="Generate HTML report")] = True,
    markdown: Annotated[bool, typer.Option("--markdown/--no-markdown", help="Generate Markdown table")] = False,
    csv_fmt: Annotated[bool, typer.Option("--csv/--no-csv", help="Generate CSV")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory (default: same dir as JSONL)")] = None,
) -> None:
    """Generate SARIF and/or HTML reports from a Petrel results JSONL."""
    if not jsonl.exists():
        err.print(f"[red]File not found: {jsonl}[/red]")
        raise typer.Exit(1)

    records: list[MCPServerRecord] = []
    for line in jsonl.read_text().splitlines():
        line = line.strip()
        if line:
            records.append(MCPServerRecord.model_validate_json(line))

    if not records:
        console.print("[yellow]No records found.[/yellow]")
        raise typer.Exit(0)

    out_dir = output if output is not None else jsonl.parent
    stem = jsonl.stem

    if sarif:
        from .output.sarif import write_sarif
        sarif_path = out_dir / f"{stem}.sarif"
        write_sarif(records, sarif_path)
        console.print(f"[dim]SARIF saved to {sarif_path}[/dim]")

    if html:
        from .output.html import write_html
        html_path = out_dir / f"{stem}.html"
        write_html(records, html_path)
        console.print(f"[dim]HTML report saved to {html_path}[/dim]")

    if markdown:
        from .output.markdown import write_markdown
        md_path = out_dir / f"{stem}.md"
        write_markdown(records, md_path)
        console.print(f"[dim]Markdown saved to {md_path}[/dim]")

    if csv_fmt:
        from .output.csv import write_csv
        csv_path = out_dir / f"{stem}.csv"
        write_csv(records, csv_path)
        console.print(f"[dim]CSV saved to {csv_path}[/dim]")

    if not sarif and not html and not markdown and not csv_fmt:
        console.print("[yellow]Nothing to generate (all formats disabled).[/yellow]")


# ---------------------------------------------------------------------------
# history / trend
# ---------------------------------------------------------------------------

@app.command()
def history() -> None:
    """Show history of Petrel discovery runs."""
    from .store import list_runs
    runs = list_runs()
    if not runs:
        print("No runs recorded yet. Run 'petrel discover' to start.")
        return
    for r in runs:
        label = r.get("label") or "(unlabeled)"
        started = (r.get("started_at") or "")[:16]
        print(f"[{r['id']:3d}] {started}  {label:30s}  confirmed={r['confirmed_count']}  critical={r['critical_count']}")


@app.command()
def trend(
    metric: Annotated[str, typer.Argument(help="Metric: confirmed_count | critical_count | target_count | auth_pct | avg_priority_score")] = "confirmed_count",
) -> None:
    """Show trend of a metric across runs."""
    from .store import get_trend
    data = get_trend(metric)
    if not data:
        print(f"No data for metric '{metric}'.")
        return
    for r in data:
        label = r.get("label") or f"run-{r['id']}"
        started = (r.get("started_at") or "")[:10]
        print(f"{started}  {label:30s}  {metric}={r.get(metric, 'N/A')}")


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
