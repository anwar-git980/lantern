"""Runs modules concurrently over one shared HTTP client.

`investigate` runs every module that supports a seed - what `osint run` does. `run_jobs` runs
an explicit (module, seed) list, which is what the agent needs once it starts choosing one
module for one pivot rather than everything for everything.
"""

import asyncio
import time

import httpx

from osint_agent.core.models import ModuleResult, Seed

CLIENT_TIMEOUT = 15.0
USER_AGENT = "lantern/0.3 (+https://github.com/anwar-git980/lantern)"


def open_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=CLIENT_TIMEOUT,
        follow_redirects=True,
        headers={"user-agent": USER_AGENT},
    )


async def _run_module(module, seed: Seed, client: httpx.AsyncClient) -> ModuleResult:
    start = time.perf_counter()
    try:
        result = await module.run(seed, client)
    except Exception as exc:  # a module must never abort the whole investigation
        result = ModuleResult(module=module.NAME, errors=[f"{type(exc).__name__}: {exc}"])
    result.duration_s = round(time.perf_counter() - start, 3)
    return result


async def run_jobs(jobs: list[tuple[object, Seed]]) -> list[ModuleResult]:
    """Run each (module, seed) pair concurrently. Results come back in the order given."""
    if not jobs:
        return []
    async with open_client() as client:
        return list(await asyncio.gather(*(_run_module(m, s, client) for m, s in jobs)))


async def investigate(seed: Seed) -> list[ModuleResult]:
    from osint_agent.modules import REGISTRY

    modules = REGISTRY.get(seed.type, [])
    if not modules:
        return []
    return await run_jobs([(module, seed) for module in modules])
