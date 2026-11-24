"""Email module tests. All HTTP is mocked with respx - these never touch the network."""

import hashlib
import json
from pathlib import Path

import httpx
import pytest
import respx

from osint_agent.modules.email import (
    HIBP_RAW_KEYS,
    _check_gravatar,
    _check_hibp,
    _check_holehe,
)

FIXTURES = Path(__file__).parent / "fixtures"
EMAIL = "testuser@example.com"
HIBP_PATTERN = "https://haveibeenpwned.com/api/v3/breachedaccount/"
GRAVATAR_DIGEST = hashlib.sha256(EMAIL.encode()).hexdigest()
GRAVATAR_URL = f"https://gravatar.com/{GRAVATAR_DIGEST}.json"

# Fields that must never survive into a Finding, whatever HIBP returns.
FORBIDDEN_RAW_KEYS = ("PasswordHash", "Passwords", "RawDumpExcerpt", "Description")


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def client():
    return httpx.AsyncClient(timeout=5, follow_redirects=True)


@respx.mock
async def test_hibp_found_returns_metadata_only(client, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "fake-key")
    respx.get(url__startswith=HIBP_PATTERN).mock(
        return_value=httpx.Response(200, json=load("hibp_two_breaches.json"))
    )

    async with client:
        findings, errors = await _check_hibp(EMAIL, client)

    assert errors == []
    assert [f.value for f in findings] == ["Adobe", "LinkedIn"]

    for finding in findings:
        assert finding.entity_type == "breach"
        assert finding.confidence == 1.0
        assert finding.source_url == "https://haveibeenpwned.com/"
        # The whitelist is the whole point: only the four metadata keys get through.
        assert set(finding.raw) == set(HIBP_RAW_KEYS)
        blob = json.dumps(finding.raw)
        for forbidden in FORBIDDEN_RAW_KEYS:
            assert forbidden not in finding.raw
        assert "SHOULD-NEVER-REACH-A-FINDING" not in blob

    adobe = findings[0]
    assert adobe.raw["BreachDate"] == "2013-10-04"
    assert adobe.raw["PwnCount"] == 152445165
    assert adobe.raw["Domain"] == "adobe.com"
    assert "Passwords" in adobe.raw["DataClasses"]  # the category name is metadata, not a secret


@respx.mock
async def test_hibp_404_is_a_clean_negative(client, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "fake-key")
    respx.get(url__startswith=HIBP_PATTERN).mock(return_value=httpx.Response(404))

    async with client:
        findings, errors = await _check_hibp(EMAIL, client)

    assert findings == []
    assert errors == []  # not breached is not an error


async def test_hibp_without_key_warns_and_does_not_crash(client, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)

    async with client:
        findings, errors = await _check_hibp(EMAIL, client)

    assert findings == []
    assert len(errors) == 1
    assert "HIBP_API_KEY not set" in errors[0]


@respx.mock
async def test_hibp_retries_once_on_429_then_reports(client, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "fake-key")
    route = respx.get(url__startswith=HIBP_PATTERN).mock(
        return_value=httpx.Response(429, headers={"retry-after": "0"})
    )

    async with client:
        findings, errors = await _check_hibp(EMAIL, client)

    assert route.call_count == 2  # original attempt plus exactly one retry
    assert findings == []
    assert "rate limited" in errors[0]


@respx.mock
async def test_gravatar_found_yields_avatar_and_linked_accounts(client):
    respx.get(GRAVATAR_URL).mock(
        return_value=httpx.Response(200, json=load("gravatar_profile.json"))
    )

    async with client:
        findings, errors = await _check_gravatar(EMAIL, client)

    assert errors == []
    by_type = {}
    for finding in findings:
        by_type.setdefault(finding.entity_type, []).append(finding)

    assert len(by_type["avatar"]) == 1
    assert by_type["avatar"][0].confidence == 1.0

    accounts = by_type["account"]
    assert len(accounts) == 3  # github, twitter, plus the one profile URL
    assert all(a.confidence == 0.9 for a in accounts)
    assert any("github.com" in a.value for a in accounts)
    assert any(a.source_url == "https://example.org/blog" for a in accounts)


@respx.mock
async def test_gravatar_404_yields_nothing(client):
    respx.get(GRAVATAR_URL).mock(return_value=httpx.Response(404))

    async with client:
        findings, errors = await _check_gravatar(EMAIL, client)

    assert (findings, errors) == ([], [])


async def test_holehe_keeps_only_existing_and_summarises_skips(monkeypatch):
    """Fake holehe at our wrapper boundary rather than testing its 120 site checks."""
    import osint_agent.modules.email as email_module

    async def fake_check_a(email, client, out):
        pass

    async def fake_check_b(email, client, out):
        pass

    async def fake_check_c(email, client, out):
        pass

    monkeypatch.setattr(
        email_module, "_holehe_checks", lambda: [fake_check_a, fake_check_b, fake_check_c]
    )

    rows = [
        {"name": "github", "domain": "github.com", "exists": True, "rateLimit": False},
        {"name": "spotify", "domain": "spotify.com", "exists": False, "rateLimit": False},
        {"name": "twitter", "domain": "twitter.com", "exists": False, "rateLimit": True},
    ]

    async def fake_launch_module(func, email, client, out):
        out.append(rows.pop(0))

    monkeypatch.setattr("holehe.core.launch_module", fake_launch_module)

    findings, errors = await _check_holehe(EMAIL)

    assert [f.value for f in findings] == ["github.com"]
    assert findings[0].entity_type == "registered_service"
    assert findings[0].confidence == 0.7
    assert len(errors) == 1
    assert "1 of 3 checks skipped" in errors[0]
