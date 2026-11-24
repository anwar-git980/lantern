"""Runs every module that supports a seed, concurrently, over one shared HTTP client."""

import asyncio
import time

import httpx

from osint_agent.core.models import ModuleResult, Seed

CLIENT_TIMEOUT = 15.0
USER_AGENT = "osint-agent/0.1"


async def _run_module(module, seed: Seed, client: httpx.AsyncClient) -> ModuleResult:
    start = time.perf_counter()
    try:
        result = await module.run(seed, client)
    except Exception as exc:  # a module must never abort the whole investigation
        result = ModuleResult(module=module.NAME, errors=[f"{type(exc).__name__}: {exc}"])
    result.duration_s = round(time.perf_counter() - start, 3)
    return result


async def investigate(seed: Seed) -> list[ModuleResult]:
    from osint_agent.modules import REGISTRY

    modules = REGISTRY.get(seed.type, [])
    if not modules:
        return []

    async with httpx.AsyncClient(
        timeout=CLIENT_TIMEOUT,
        follow_redirects=True,
        headers={"user-agent": USER_AGENT},
    ) as client:
        return list(await asyncio.gather(*(_run_module(m, seed, client) for m in modules)))
