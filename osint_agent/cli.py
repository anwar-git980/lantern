"""Command line entry point."""

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint_agent.agent.loop import (
    DEFAULT_MODEL,
    MAX_DEPTH,
    MAX_TOOL_CALLS,
    investigate_agent,
)
from osint_agent.core import http, scoring
from osint_agent.core.graph import EntityGraph
from osint_agent.core.models import ModuleResult, Seed, SeedType, looks_like_hostname
from osint_agent.core.runner import investigate as run_all_modules

NOTICE = "Use only on targets you're authorized to investigate. See ACCEPTABLE_USE.md."
VALUE_WIDTH = 60

if sys.platform == "win32":
    # The legacy console codepage mangles the box-drawing and ellipsis characters Rich emits.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(add_completion=False, help="Modular OSINT agent for authorized investigations.")
console = Console()


@app.callback()
def main() -> None:
    """Modular OSINT agent for authorized investigations."""
    # Present so Typer keeps `run` as a subcommand instead of collapsing it to the root.


def _seed_from_options(
    email: str | None,
    username: str | None,
    phone: str | None,
    domain: str | None,
    name: str | None,
) -> Seed:
    provided = {
        SeedType.email: email,
        SeedType.username: username,
        SeedType.phone: phone,
        SeedType.domain: domain,
        SeedType.name: name,
    }
    given = {seed_type: value for seed_type, value in provided.items() if value}

    if len(given) != 1:
        console.print(
            "[red]Provide exactly one of --email, --username, --phone, --domain or --name.[/red]"
        )
        raise typer.Exit(code=2)

    seed_type, value = next(iter(given.items()))
    seed = Seed(type=seed_type, value=value)

    if seed_type is SeedType.domain and not looks_like_hostname(seed.normalized):
        console.print(f"[red]{value!r} does not look like a domain name.[/red]")
        raise typer.Exit(code=2)
    return seed


def _log_http_to_stderr() -> None:
    # Our own HTTP logger only: third-party debug output would bury the findings.
    logger = logging.getLogger("osint_agent.http")
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


def _render(result: ModuleResult, verbose: bool) -> None:
    table = Table(
        title=f"{result.module}  ({len(result.findings)} findings, {result.duration_s}s)",
        title_justify="left",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("entity_type", style="green", no_wrap=True)
    table.add_column("value")
    table.add_column("conf", justify="right", width=5)
    table.add_column("source", style="dim")

    for finding in sorted(result.findings, key=lambda f: (f.entity_type, f.value)):
        value = finding.value
        if not verbose and len(value) > VALUE_WIDTH:
            value = value[: VALUE_WIDTH - 3] + "..."
        table.add_row(
            finding.entity_type,
            value,
            f"{finding.confidence:.2f}",
            finding.source_url or "",
        )

    if result.findings:
        console.print(table)
    else:
        console.print(f"[dim]{result.module}: no findings ({result.duration_s}s)[/dim]")

    if verbose:
        for finding in result.findings:
            if finding.raw:
                console.print(f"  [dim]{finding.entity_type} raw: {finding.raw}[/dim]")


@app.command()
def run(
    email: str = typer.Option(None, "--email", help="Email address to investigate."),
    username: str = typer.Option(None, "--username", help="Username to investigate."),
    phone: str = typer.Option(None, "--phone", help="Phone number to investigate."),
    domain: str = typer.Option(None, "--domain", help="Domain name to investigate."),
    name: str = typer.Option(None, "--name", help="Person name to investigate."),
    json_path: Path = typer.Option(None, "--json", help="Write full results to this JSON file."),
    verbose: bool = typer.Option(False, "--verbose", help="Show raw payloads and full values."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Ignore cached responses. Fresh ones are still cached."
    ),
) -> None:
    """Run every module that supports the given seed."""
    load_dotenv()
    if verbose:
        _log_http_to_stderr()
    if no_cache:
        http.read_cache = False
    console.print(f"[dim]{NOTICE}[/dim]\n")

    seed = _seed_from_options(email, username, phone, domain, name)
    console.print(f"[bold]seed:[/bold] {seed.type} = {seed.normalized}\n")

    started = time.perf_counter()
    results = asyncio.run(run_all_modules(seed))
    elapsed = round(time.perf_counter() - started, 2)

    if not results:
        console.print(f"[yellow]No modules registered for seed type {seed.type}.[/yellow]")
        raise typer.Exit(code=1)

    for result in results:
        _render(result, verbose)
        console.print()

    problems = [f"[{r.module}] {e}" for r in results for e in r.errors]
    if problems:
        console.print(
            Panel(
                "\n".join(problems),
                title="warnings / errors",
                border_style="yellow",
                title_align="left",
            )
        )

    total = sum(len(r.findings) for r in results)
    console.print(f"\n[bold]{total} findings[/bold] from {len(results)} module(s) in {elapsed}s")

    if json_path:
        payload = {
            "seed": seed.model_dump(mode="json") | {"normalized": seed.normalized},
            "results": [r.model_dump(mode="json") for r in results],
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]wrote[/green] {json_path}")


NODE_ROWS_PER_TYPE = 15


def _node_table(record) -> Table:
    """Every node the run established, grouped by type, strongest first."""
    found = EntityGraph.from_dict(record.graph)

    table = Table(
        title="entities",
        title_justify="left",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("type", style="green", no_wrap=True)
    table.add_column("value")
    table.add_column("conf", justify="right", width=5)
    table.add_column("label", no_wrap=True)

    for node_type, values in found.by_type().items():
        for value, confidence in values[:NODE_ROWS_PER_TYPE]:
            shown = value if len(value) <= VALUE_WIDTH else value[: VALUE_WIDTH - 3] + "..."
            tag = scoring.label(confidence)
            table.add_row(
                node_type,
                shown,
                f"{confidence:.2f}",
                f"[{LABEL_STYLES[tag]}]{tag}[/{LABEL_STYLES[tag]}]",
            )
        if len(values) > NODE_ROWS_PER_TYPE:
            table.add_row("", f"[dim]+{len(values) - NODE_ROWS_PER_TYPE} more[/dim]", "", "")
    return table


LABEL_STYLES = {"strong": "bold green", "likely": "yellow", "possible": "dim"}


@app.command()
def investigate(
    email: str = typer.Option(None, "--email", help="Email address to investigate."),
    username: str = typer.Option(None, "--username", help="Username to investigate."),
    phone: str = typer.Option(None, "--phone", help="Phone number to investigate."),
    domain: str = typer.Option(None, "--domain", help="Domain name to investigate."),
    name: str = typer.Option(None, "--name", help="Person name to investigate."),
    depth: int = typer.Option(MAX_DEPTH, "--depth", help="How many pivots deep to go."),
    max_calls: int = typer.Option(
        MAX_TOOL_CALLS, "--max-calls", help="Hard cap on module runs for the whole investigation."
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Skip the planner; expand breadth-first instead."
    ),
    graph_path: Path = typer.Option(None, "--graph", help="Write the entity graph to this file."),
    json_path: Path = typer.Option(None, "--json", help="Write the full run record here."),
    verbose: bool = typer.Option(False, "--verbose", help="Log every fetch and cache hit."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Ignore cached responses. Fresh ones are still cached."
    ),
) -> None:
    """Pivot from one seed into a scored entity graph, planning each step with an LLM."""
    load_dotenv()
    if verbose:
        _log_http_to_stderr()
    if no_cache:
        http.read_cache = False
    http.stats.update(fetches=0, cache_hits=0)
    console.print(f"[dim]{NOTICE}[/dim]\n")

    seed = _seed_from_options(email, username, phone, domain, name)

    have_key = bool(os.getenv("ANTHROPIC_API_KEY"))
    use_llm = not no_llm and have_key
    if no_llm:
        console.print("[yellow]--no-llm: expanding breadth-first, which is noisier.[/yellow]")
    elif not have_key:
        console.print(
            "[yellow]ANTHROPIC_API_KEY not set - falling back to breadth-first expansion, "
            "which is noisier.[/yellow]"
        )

    model = os.getenv("LANTERN_MODEL") or DEFAULT_MODEL
    console.print(f"[bold]seed:[/bold] {seed.type} = {seed.normalized}")
    console.print(
        f"[dim]mode:[/dim] {'planner ' + model if use_llm else 'breadth-first'}  "
        f"[dim]depth:[/dim] {depth}  [dim]max module runs:[/dim] {max_calls}\n"
    )

    started = time.perf_counter()
    record = asyncio.run(
        investigate_agent(
            seed,
            max_depth=depth,
            max_tool_calls=max_calls,
            use_llm=use_llm,
            on_step=lambda text: console.print(f"  [dim]>[/dim] {text}"),
        )
    )
    elapsed = round(time.perf_counter() - started, 2)

    console.print()
    console.print(_node_table(record))

    if record.summary:
        console.print(
            Panel(record.summary, title="planner summary", border_style="cyan", title_align="left")
        )

    console.print(
        f"\n[bold]stopped:[/bold] {record.stop_reason}\n"
        f"module runs: {record.tool_calls}   planning turns: {record.llm_turns}   "
        f"nodes: {len(record.graph.get('nodes', []))}   edges: {len(_links(record.graph))}\n"
        f"tokens: {record.usage['input_tokens']} in / {record.usage['output_tokens']} out   "
        f"fetches: {http.stats['fetches']}   cache hits: {http.stats['cache_hits']}   "
        f"elapsed: {elapsed}s"
    )

    if record.warnings:
        console.print(
            Panel(
                "\n".join(record.warnings),
                title="warnings / errors",
                border_style="yellow",
                title_align="left",
            )
        )

    if record.rejected:
        lines = [
            f"[{r.kind}] turn {r.turn}: {r.tool}({r.value!r}) - {r.reason}" for r in record.rejected
        ]
        suspects = len(record.suspects)
        console.print(
            Panel(
                "\n".join(lines),
                title=f"rejected tool calls ({suspects} possible injection)",
                border_style="red",
                title_align="left",
            )
        )

    if graph_path:
        graph_path.write_text(json.dumps(record.graph, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]wrote[/green] {graph_path}")

    if json_path:
        json_path.write_text(
            json.dumps(record.model_dump(mode="json"), indent=2, default=str), encoding="utf-8"
        )
        console.print(f"[green]wrote[/green] {json_path}")


def _links(graph: dict) -> list:
    """node_link_data names the edge list "links" on networkx 2.x and "edges" on 3.6+."""
    return graph.get("links") or graph.get("edges") or []


if __name__ == "__main__":
    app()
