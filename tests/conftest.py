"""Test isolation: a throwaway cache file and no inherited or real rate-limit delays."""

import httpx
import pytest

from osint_agent.core import cache, ratelimit


@pytest.fixture(autouse=True)
def isolate_http_state(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "DB_PATH", tmp_path / "cache.db")
    monkeypatch.setattr(ratelimit, "LIMITS", {})
    monkeypatch.setattr(ratelimit, "DEFAULT_DELAY", 0.0)
    ratelimit.reset()
    yield
    ratelimit.reset()


@pytest.fixture
async def client():
    async with httpx.AsyncClient(timeout=5, follow_redirects=True) as open_client:
        yield open_client
