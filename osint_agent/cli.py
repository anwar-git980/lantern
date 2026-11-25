"""Command line entry point."""

import asyncio
import json
import logging
import sys
import time
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint_agent.core import http
from osint_agent.core.models import ModuleResult, Seed, SeedType, looks_like_hostname
from osint_agent.core.runner import investigate

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
    results = asyncio.run(investigate(seed))
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


if __name__ == "__main__":
    app()
