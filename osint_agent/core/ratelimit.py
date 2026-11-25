"""Per-host request spacing: one lock and one timestamp per host, nothing more."""

import asyncio
import time
from urllib.parse import urlparse

# Seconds to leave between requests to the same host, from each service's published limit.
LIMITS = {
    "haveibeenpwned.com": 1.6,
    "crt.sh": 2.0,
    "rdap.org": 1.0,
    "internetdb.shodan.io": 1.0,
    "web.archive.org": 1.0,
    "api.github.com": 0.5,
    "www.reddit.com": 2.0,
    "public.api.bsky.app": 0.5,
    "hn.algolia.com": 0.5,
    "api.search.brave.com": 1.1,
    "gravatar.com": 0.5,
}
DEFAULT_DELAY = 0.5

_locks: dict[str, asyncio.Lock] = {}
_last_request: dict[str, float] = {}


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


async def acquire(host: str) -> None:
    """Wait out this host's quiet period, then claim the slot."""
    delay = LIMITS.get(host, DEFAULT_DELAY)
    lock = _locks.setdefault(host, asyncio.Lock())
    # The lock is held across the sleep so concurrent callers queue up instead of all
    # reading the same stale timestamp and firing together.
    async with lock:
        wait = delay - (time.monotonic() - _last_request.get(host, 0.0))
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request[host] = time.monotonic()


def reset() -> None:
    """Drop all state. Tests need it: a Lock binds to the loop that first awaits it."""
    _locks.clear()
    _last_request.clear()
