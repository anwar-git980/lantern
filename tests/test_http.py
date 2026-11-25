"""Shared HTTP layer: caching, 429 handling, credential hygiene and per-host spacing."""

import json
import sqlite3
import time

import httpx
import respx

from osint_agent.core import cache, ratelimit
from osint_agent.core.http import fetch_json

URL = "https://example.test/api"


def stored_rows():
    # Nothing cached means the file was never even created, which counts as no rows.
    if not cache.DB_PATH.exists():
        return []
    with sqlite3.connect(cache.DB_PATH) as conn:
        return conn.execute("SELECT key, status, body FROM responses").fetchall()


@respx.mock
async def test_second_identical_call_is_served_from_cache(client):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"hello": "world"}))

    first = await fetch_json(client, URL)
    second = await fetch_json(client, URL)

    assert first == second == (200, {"hello": "world"})
    assert route.call_count == 1  # the second call never reached the network


@respx.mock
async def test_404_is_cached_because_not_found_is_an_answer(client):
    route = respx.get(URL).mock(return_value=httpx.Response(404, text="nope"))

    assert await fetch_json(client, URL) == (404, None)
    assert await fetch_json(client, URL) == (404, None)
    assert route.call_count == 1


@respx.mock
async def test_429_retries_once_and_is_never_cached(client):
    route = respx.get(URL).mock(return_value=httpx.Response(429, headers={"retry-after": "0"}))

    status, _ = await fetch_json(client, URL)

    assert status == 429
    assert route.call_count == 2  # the original attempt plus exactly one retry
    assert stored_rows() == []

    await fetch_json(client, URL)
    assert route.call_count == 4  # nothing was cached, so it went back to the network


@respx.mock
async def test_credentials_never_reach_the_cache(client):
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    secret = "super-secret-subscription-token"

    await fetch_json(
        client,
        URL,
        headers={"x-subscription-token": secret},
        params={"q": "lantern", "api_key": secret},
    )

    rows = stored_rows()
    assert rows, "the response should have been cached"
    assert secret not in json.dumps(rows)


def test_cache_key_ignores_credential_params_but_not_real_ones():
    with_key_a = cache.cache_key("GET", URL, {"q": "x", "api_key": "aaa"})
    with_key_b = cache.cache_key("GET", URL, {"q": "x", "api_key": "bbb"})
    other_query = cache.cache_key("GET", URL, {"q": "y"})

    assert with_key_a == with_key_b
    assert with_key_a != other_query


def test_put_refuses_uncacheable_statuses():
    for status in (429, 500, 503):
        cache.put(f"key-{status}", status, "body", ttl=60)
    assert stored_rows() == []


def test_expired_entries_are_not_returned():
    cache.put("stale", 200, "body", ttl=-1)
    assert cache.get("stale") is None


@respx.mock
async def test_requests_to_one_host_are_spaced_apart(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "DEFAULT_DELAY", 0.05)
    respx.get(URL).mock(return_value=httpx.Response(200, json={"n": 1}))

    started = time.perf_counter()
    # Distinct params so the second request is a cache miss and really goes out.
    await fetch_json(client, URL, params={"n": 1})
    await fetch_json(client, URL, params={"n": 2})
    elapsed = time.perf_counter() - started

    assert elapsed >= 0.05


@respx.mock
async def test_cache_can_be_bypassed_per_call(client):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))

    await fetch_json(client, URL, cache=False)
    await fetch_json(client, URL, cache=False)

    assert route.call_count == 2
    assert stored_rows() == []
