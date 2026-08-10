"""Petrel watch — continuous re-probe of CRITICAL exec-cluster servers."""
from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn

from . import __version__
from . import store as _store
from .fingerprint.probe import probe_url
from .models import MCPServerRecord
from .scoring.risk import score_server
from .store import create_run, finish_run, insert_run_snapshots, update_server_history

console = Console()
err = Console(stderr=True)

# Exec-family cluster keys produced by scoring/risk.py _detect_clusters()
_EXEC_CLUSTER_KEYS: frozenset[str] = frozenset({"exec+network", "exec+messaging", "redundant_exec"})

# Shared-hosting platforms that warrant per-domain throttling (matches probe.py _THROTTLE_DOMAINS)
_THROTTLE_SUFFIXES: tuple[str, ...] = (
    ".railway.app", ".hf.space", ".fly.dev", ".fly.io", ".onrender.com", ".vercel.app"
)


def _get_watch_targets(max_age_days: int = 7) -> list[dict]:
    """Return CRITICAL exec-cluster servers from the last discover run.

    Queries ``server_run_snapshots`` for the most recent run and filters to rows
    whose ``risk_tier`` is CRITICAL and whose ``capability_cluster`` contains at
    least one exec-family key.  Warns if that run is older than *max_age_days*.
    """
    if not _store.DB_PATH.exists():
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    conn = sqlite3.connect(str(_store.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        last_run = conn.execute(
            "SELECT id, finished_at FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not last_run:
            return []
        last_run_id = last_run["id"]

        finished_at = last_run["finished_at"] or ""
        if finished_at and finished_at < cutoff:
            console.print(
                f"[yellow]Last run ({finished_at[:10]}) is older than "
                f"{max_age_days}d — targets may be stale.[/yellow]"
            )

        rows = conn.execute(
            "SELECT url, risk_tier, capability_cluster, priority_score, auth_state "
            "FROM server_run_snapshots "
            "WHERE run_id = ? AND risk_tier = 'CRITICAL'",
            (last_run_id,),
        ).fetchall()
    finally:
        conn.close()

    targets: list[dict] = []
    for row in rows:
        d = dict(row)
        try:
            clusters: set[str] = set(json.loads(d.get("capability_cluster") or "[]"))
        except Exception:
            clusters = set()
        if clusters & _EXEC_CLUSTER_KEYS:
            targets.append(d)
    return targets


def _get_throttle_suffix(url: str) -> str | None:
    """Return the matching throttle suffix if *url* is on a rate-limited platform."""
    url_lower = url.lower()
    return next((s for s in _THROTTLE_SUFFIXES if s in url_lower), None)


async def _probe_with_throttle(
    url: str,
    client: httpx.AsyncClient,
    domain_sems: dict[str, asyncio.Semaphore],
) -> MCPServerRecord | None:
    """Probe *url*, acquiring a per-domain Semaphore(3) for throttled platforms."""
    suffix = _get_throttle_suffix(url)
    if suffix:
        if suffix not in domain_sems:
            domain_sems[suffix] = asyncio.Semaphore(3)
        async with domain_sems[suffix]:
            return await probe_url(url, client)
    return await probe_url(url, client)


async def _run_watch_round(targets: list[dict], round_num: int) -> list[MCPServerRecord]:
    """Probe all *targets*, score results, and persist a run + snapshots.

    Returns the list of confirmed (still-live) records after this round.
    """
    domain_sems: dict[str, asyncio.Semaphore] = {}
    confirmed: list[MCPServerRecord] = []
    run_id = create_run(label=f"watch-round-{round_num}", source="watch")

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            MofNCompleteColumn(),
            console=err,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Watch round {round_num} ({len(targets)} targets)...",
                total=len(targets),
            )

            async def _probe_one(t: dict) -> None:
                url = t["url"]
                progress.update(task, description=f"[cyan]probing {url[:55]}...")
                try:
                    record = await _probe_with_throttle(url, client, domain_sems)
                except Exception as exc:
                    err.print(f"[dim]Error probing {url}: {exc}[/dim]")
                    progress.advance(task)
                    return
                finally:
                    progress.advance(task)

                if record is not None and record.is_confirmed_mcp:
                    scored = score_server(record)
                    scored.petrel_version = __version__
                    confirmed.append(scored)
                    console.print(
                        f"  [bold]ALIVE[/bold]  [red]{scored.risk_tier.value}[/red]  "
                        f"{url}  auth={scored.auth_state.value}"
                    )
                else:
                    console.print(f"  [dim]GONE   {url}[/dim]")

            await asyncio.gather(*[_probe_one(t) for t in targets])

    finish_run(run_id, confirmed)
    n_snaps = insert_run_snapshots(run_id, confirmed)
    _decay = update_server_history(run_id, [r.url for r in confirmed])

    console.print(
        f"[dim]Round {round_num}: {len(confirmed)}/{len(targets)} alive  "
        f"| {n_snaps} snapshots  "
        f"| {_decay.get('new', 0)} new, {_decay.get('decayed', 0)} decayed[/dim]"
    )
    return confirmed


def watch_command(
    interval: Annotated[int, typer.Option("--interval", "-i", help="Hours between re-probe rounds")] = 6,
    max_rounds: Annotated[int, typer.Option("--max-rounds", "-n", help="Max rounds (0 = infinite)")] = 0,
) -> None:
    """Re-probe CRITICAL exec-cluster servers from the last petrel discover run.

    Reads CRITICAL servers whose ``capability_cluster`` contains exec-family keys
    (exec+network, exec+messaging, redundant_exec) from the latest petrel discover
    run stored in ``~/.petrel/runs.db``.  Re-probes them every ``--interval`` hours,
    applying per-domain Semaphore(3) throttling for shared hosting platforms.
    Stores a new run + snapshots after each round for longitudinal tracking.

    Press Ctrl+C to stop.
    """
    targets = _get_watch_targets()
    if not targets:
        console.print(
            "[yellow]No CRITICAL exec-cluster targets found in last run. "
            "Run 'petrel discover' first.[/yellow]"
        )
        raise typer.Exit(0)

    max_label = "infinite" if max_rounds == 0 else str(max_rounds)
    console.print(
        f"[bold cyan]Petrel Watch[/bold cyan] — {len(targets)} target(s)  "
        f"interval={interval}h  max_rounds={max_label}"
    )
    for t in targets:
        console.print(f"  [dim]{t['url']}[/dim]")
    console.print()

    round_num = 0

    async def _loop() -> None:
        nonlocal round_num
        while True:
            round_num += 1
            console.print(f"\n[bold]── Round {round_num} ──[/bold]")
            await _run_watch_round(targets, round_num)

            if max_rounds > 0 and round_num >= max_rounds:
                console.print(f"[dim]Reached max_rounds={max_rounds}. Done.[/dim]")
                break

            console.print(f"[dim]Next round in {interval}h (Ctrl+C to stop)...[/dim]")
            await asyncio.sleep(interval * 3600)

    try:
        asyncio.run(_loop())
    except KeyboardInterrupt:
        console.print(f"\n[dim]Watch stopped after {round_num} round(s).[/dim]")
