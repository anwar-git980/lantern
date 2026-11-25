"""Dork module tests: template loading, per-seed-type formatting, dedupe and key handling."""

import httpx
import respx

from osint_agent.core.models import Seed, SeedType
from osint_agent.modules import dork

BRAVE = "https://api.search.brave.com"

SEEDS = {
    SeedType.email: Seed(type=SeedType.email, value="Someone@Example.com"),
    SeedType.username: Seed(type=SeedType.username, value="@jdoe"),
    SeedType.phone: Seed(type=SeedType.phone, value="+60123456789"),
    SeedType.domain: Seed(type=SeedType.domain, value="https://www.Example.com/path"),
    SeedType.name: Seed(type=SeedType.name, value="  Jane   Doe  "),
}


def two_results(title_prefix="Hit"):
    return {
        "web": {
            "results": [
                {"title": title_prefix, "url": "https://a.test/1", "description": "first"},
                {"title": "Same URL again", "url": "https://a.test/1", "description": "dupe"},
                {"title": "Second", "url": "https://a.test/2", "description": "second"},
            ]
        }
    }


def test_every_seed_type_has_a_usable_starter_set():
    for seed_type in SeedType:
        entries = dork.load_dorks(seed_type)
        assert 4 <= len(entries) <= 8, f"{seed_type} has {len(entries)} dorks"
        ids = [entry["id"] for entry in entries]
        assert len(set(ids)) == len(ids), f"{seed_type} has duplicate dork ids"


def test_templates_render_against_their_own_seed_type():
    for seed_type, seed in SEEDS.items():
        context = dork._context(seed)
        for entry in dork.load_dorks(seed_type):
            rendered = entry["query"].format(**context)
            assert "{" not in rendered, f"{entry['id']} left a placeholder unfilled"
            assert seed.normalized in rendered or context.get("national", "") in rendered


def test_phone_context_offers_both_formats():
    context = dork._context(SEEDS[SeedType.phone])

    assert context["value"] == "+60123456789"
    assert context["national"] != context["value"]
    assert "12" in context["national"]


async def test_missing_key_skips_the_module_with_one_warning(client, monkeypatch):
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)

    result = await dork.run(SEEDS[SeedType.email], client)

    assert result.findings == []
    assert len(result.errors) == 1
    assert "BRAVE_API_KEY not set" in result.errors[0]


@respx.mock
async def test_results_become_findings_and_are_deduped_by_url(client, monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    monkeypatch.setattr(dork, "MAX_DORKS", 2)
    respx.get(url__startswith=BRAVE).mock(return_value=httpx.Response(200, json=two_results()))

    result = await dork.run(SEEDS[SeedType.username], client)

    assert result.errors == []
    assert [f.source_url for f in result.findings] == ["https://a.test/1", "https://a.test/2"]
    assert all(f.entity_type == "dork_hit" for f in result.findings)
    assert all(f.confidence == 0.5 for f in result.findings)

    first = result.findings[0]
    assert first.value == "Hit"
    assert first.raw["dork_id"] == dork.load_dorks(SeedType.username)[0]["id"]
    assert first.raw["snippet"] == "first"
    assert "jdoe" in first.raw["query"]


@respx.mock
async def test_at_most_max_dorks_queries_are_sent(client, monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    monkeypatch.setattr(dork, "MAX_DORKS", 3)
    route = respx.get(url__startswith=BRAVE).mock(
        return_value=httpx.Response(200, json={"web": {"results": []}})
    )

    await dork.run(SEEDS[SeedType.domain], client)

    assert route.call_count == 3


@respx.mock
async def test_a_rejected_key_stops_after_one_dork(client, monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "wrong-key")
    route = respx.get(url__startswith=BRAVE).mock(return_value=httpx.Response(401))

    result = await dork.run(SEEDS[SeedType.email], client)

    assert route.call_count == 1  # no point burning the rest of the dorks
    assert result.findings == []
    assert "rejected the API key" in result.errors[0]


async def test_an_unknown_seed_type_template_set_warns(client, monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    monkeypatch.setattr(dork, "DORKS_DIR", dork.DORKS_DIR / "does-not-exist")

    result = await dork.run(SEEDS[SeedType.name], client)

    assert result.findings == []
    assert "no dork templates found" in result.errors[0]
