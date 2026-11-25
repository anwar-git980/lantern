"""The one HTTP entry point every module uses: caches, spaces per host, retries once on 429."""

import asyncio
import json
import logging
from typing import Any

import httpx

from osint_agent.core import cache as response_cache
from osint_agent.core import ratelimit

logger = logging.getLogger("osint_agent.http")

MAX_RETRY_AFTER = 30.0
DEFAULT_TTL = 86400.0

# --no-cache clears this. Writes continue regardless, so the next run still benefits.
read_cache = True


def _retry_delay(response: httpx.Response) -> float:
    try:
        return min(float(response.headers.get("retry-after", "2")), MAX_RETRY_AFTER)
    except ValueError:
        return 2.0


def _parse(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return None


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    ttl: float = DEFAULT_TTL,
    cache: bool = True,
    timeout: float | None = None,
) -> tuple[int, Any]:
    """GET url, returning (status code, parsed JSON or None when the body is not JSON).

    Transport errors propagate: every caller already reports its own failures, and a
    connection reset is not a result worth caching.
    """
    key = response_cache.cache_key("GET", url, params)
    if cache and read_cache:
        hit = response_cache.get(key)
        if hit is not None:
            logger.debug("cache hit  %s", url)
            return hit[0], _parse(hit[1])

    request_args: dict[str, Any] = {"params": params, "headers": headers}
    if timeout is not None:
        request_args["timeout"] = timeout

    await ratelimit.acquire(ratelimit.host_of(url))
    logger.debug("fetch      %s", url)
    response = await client.get(url, **request_args)

    if response.status_code == 429:
        await asyncio.sleep(_retry_delay(response))
        await ratelimit.acquire(ratelimit.host_of(url))
        response = await client.get(url, **request_args)

    if cache:
        response_cache.put(key, response.status_code, response.text, ttl)
    return response.status_code, _parse(response.text)
