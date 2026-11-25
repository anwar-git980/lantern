"""Search-engine dorking through the Brave Search API.

Queries live in dorks/<seed type>.yaml so adding one needs no code change. Only Brave's
documented API is called: no search-result HTML is ever scraped.
"""

import os
from pathlib import Path

import httpx
import phonenumbers
import yaml

from osint_agent.core.http import fetch_json
from osint_agent.core.models import DEFAULT_REGION, Finding, ModuleResult, Seed, SeedType

NAME = "dork"
SUPPORTS = {"email", "username", "phone", "domain", "name"}

BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
DORKS_DIR = Path(__file__).resolve().parents[2] / "dorks"
MAX_DORKS = 8
MAX_RESULTS = 10
TTL = 21600.0  # 6h: search results move faster than DNS or certificate data


def load_dorks(seed_type: SeedType) -> list[dict]:
    """Templates for this seed type. Entries missing an id or query are ignored."""
    path = DORKS_DIR / f"{seed_type.value}.yaml"
    if not path.is_file():
        return []
    entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("id") and entry.get("query")
    ]


def _context(seed: Seed) -> dict[str, str]:
    """Placeholder values a template can use: {value} always, {national} for phone seeds."""
    value = seed.normalized
    context = {"value": value}
    if seed.type is SeedType.phone:
        try:
            parsed = phonenumbers.parse(value, DEFAULT_REGION)
        except phonenumbers.NumberParseException:
            context["national"] = value
        else:
            context["national"] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            )
    return context


async def run(seed: Seed, client: httpx.AsyncClient) -> ModuleResult:
    result = ModuleResult(module=NAME)

    api_key = os.getenv("BRAVE_API_KEY")
    if not api_key:
        result.errors.append("BRAVE_API_KEY not set - search dorking skipped")
        return result

    dorks = load_dorks(seed.type)
    if not dorks:
        result.errors.append(f"no dork templates found for seed type {seed.type}")
        return result

    context = _context(seed)
    # The key travels in a header, so it never reaches a cache key or the cache file.
    headers = {"x-subscription-token": api_key, "accept": "application/json"}
    seen: set[str] = set()

    for dork in dorks[:MAX_DORKS]:
        try:
            query = dork["query"].format(**context)
        except KeyError as exc:
            result.errors.append(f"dork {dork['id']}: unknown placeholder {exc}")
            continue

        try:
            status, data = await fetch_json(
                client,
                BRAVE_URL,
                params={"q": query, "count": MAX_RESULTS},
                headers=headers,
                ttl=TTL,
            )
        except Exception as exc:
            result.errors.append(f"dork {dork['id']} failed: {type(exc).__name__}: {exc}")
            continue

        if status in (401, 403):
            result.errors.append("Brave Search rejected the API key - remaining dorks skipped")
            break
        if status == 429:
            result.errors.append("Brave Search rate limited - remaining dorks skipped")
            break
        if status != 200 or not isinstance(data, dict):
            result.errors.append(f"dork {dork['id']}: Brave returned HTTP {status}")
            continue

        for item in ((data.get("web") or {}).get("results") or [])[:MAX_RESULTS]:
            url = item.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            result.findings.append(
                Finding(
                    module=NAME,
                    entity_type="dork_hit",
                    value=item.get("title") or url,
                    source_url=url,
                    confidence=0.5,
                    raw={
                        "dork_id": dork["id"],
                        "query": query,
                        "snippet": item.get("description"),
                    },
                )
            )

    return result
