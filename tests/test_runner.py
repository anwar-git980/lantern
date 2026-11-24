"""Runner tests: module isolation, so one broken module cannot sink an investigation."""

import osint_agent.modules as modules_pkg
from osint_agent.core.models import Finding, ModuleResult, Seed, SeedType
from osint_agent.core.runner import investigate


class GoodModule:
    NAME = "good"
    SUPPORTS = {"phone"}

    async def run(self, seed, client):
        return ModuleResult(
            module=self.NAME,
            findings=[
                Finding(module=self.NAME, entity_type="carrier", value="Maxis", confidence=0.8)
            ],
        )


class ExplodingModule:
    NAME = "exploding"
    SUPPORTS = {"phone"}

    async def run(self, seed, client):
        raise RuntimeError("upstream API melted")


class WarningModule:
    NAME = "warner"
    SUPPORTS = {"phone"}

    async def run(self, seed, client):
        return ModuleResult(module=self.NAME, errors=["API key missing - skipped"])


async def test_exception_in_one_module_does_not_stop_the_others(monkeypatch):
    monkeypatch.setitem(
        modules_pkg.REGISTRY,
        SeedType.phone,
        [GoodModule(), ExplodingModule(), WarningModule()],
    )

    results = await investigate(Seed(type=SeedType.phone, value="+60123456789"))
    by_name = {r.module: r for r in results}

    assert set(by_name) == {"good", "exploding", "warner"}

    # The healthy module still produced its finding.
    assert len(by_name["good"].findings) == 1
    assert by_name["good"].errors == []

    # The raised exception was captured as an error, not propagated.
    assert by_name["exploding"].findings == []
    assert len(by_name["exploding"].errors) == 1
    assert "RuntimeError" in by_name["exploding"].errors[0]
    assert "upstream API melted" in by_name["exploding"].errors[0]

    # A module-reported warning survives the round trip.
    assert by_name["warner"].errors == ["API key missing - skipped"]


async def test_every_module_is_timed(monkeypatch):
    monkeypatch.setitem(modules_pkg.REGISTRY, SeedType.phone, [GoodModule(), ExplodingModule()])

    results = await investigate(Seed(type=SeedType.phone, value="+60123456789"))

    assert all(isinstance(r.duration_s, float) and r.duration_s >= 0.0 for r in results)


async def test_unregistered_seed_type_returns_no_results(monkeypatch):
    monkeypatch.setitem(modules_pkg.REGISTRY, SeedType.domain, [])

    assert await investigate(Seed(type=SeedType.domain, value="example.com")) == []
