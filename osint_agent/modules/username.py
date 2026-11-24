"""Username enrichment: claimed accounts across the top Maigret sites.

Uses Maigret as a library rather than a subprocess - `maigret.search` returns the per-site
results directly, so there is no JSON round-trip to parse.
"""

import logging
from pathlib import Path

import maigret

from osint_agent.core.models import Finding, ModuleResult, Seed

NAME = "username"
SUPPORTS = {"username"}

TOP_SITES = 500
SITE_TIMEOUT = 10
# Maigret ships its site database inside the installed package.
DB_PATH = Path(maigret.__file__).parent / "resources" / "data.json"


def _quiet_logger() -> logging.Logger:
    """Maigret logs a warning per site whose entry overrides its engine, which would bury
    our own CLI output. Silence that and hand `search` a logger that goes nowhere."""
    logging.getLogger("maigret.sites").setLevel(logging.ERROR)
    logger = logging.getLogger("osint_agent.maigret")
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    return logger


async def run(seed: Seed, client) -> ModuleResult:
    result = ModuleResult(module=NAME)
    username = seed.normalized
    if not username:
        result.errors.append("empty username")
        return result

    logger = _quiet_logger()

    try:
        # load_from_path does a substring test on its argument, so it needs a str not a Path.
        database = maigret.MaigretDatabase().load_from_path(str(DB_PATH))
    except Exception as exc:
        result.errors.append(f"could not load Maigret site database: {type(exc).__name__}: {exc}")
        return result

    sites = database.ranked_sites_dict(top=TOP_SITES, disabled=False)
    if not sites:
        result.errors.append("Maigret site database produced no enabled sites")
        return result

    try:
        search_results = await maigret.search(
            username,
            sites,
            logger,
            timeout=SITE_TIMEOUT,
            no_progressbar=True,
        )
    except Exception as exc:
        result.errors.append(f"Maigret search failed: {type(exc).__name__}: {exc}")
        return result

    inconclusive = 0
    for site_name, data in search_results.items():
        status = data.get("status")
        if status is None:
            inconclusive += 1
            continue
        if not status.is_found():
            # AVAILABLE is a real negative; UNKNOWN means the check could not decide.
            if getattr(status, "error", None) is not None:
                inconclusive += 1
            continue
        result.findings.append(
            Finding(
                module=NAME,
                entity_type="account",
                value=site_name,
                source_url=data.get("url_user"),
                # A username match alone is weak evidence; correlation raises this in week 2.
                confidence=0.4,
                raw={"site": site_name, "url_main": data.get("url_main")},
            )
        )

    if inconclusive:
        result.errors.append(
            f"Maigret: {inconclusive} of {len(search_results)} sites inconclusive "
            "(blocked, timed out or bot-protected)"
        )
    return result
