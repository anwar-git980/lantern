"""Phone module tests. Fully offline - phonenumbers ships its own metadata."""

from osint_agent.core.models import Seed, SeedType
from osint_agent.modules import phone


def types(result):
    return {f.entity_type for f in result.findings}


def value_of(result, entity_type):
    return next(f.value for f in result.findings if f.entity_type == entity_type)


async def test_valid_malaysian_mobile():
    seed = Seed(type=SeedType.phone, value="+60123456789")
    result = await phone.run(seed, client=None)

    assert result.errors == []
    assert {"validity", "e164", "international_format", "region", "line_type"} <= types(result)
    assert value_of(result, "e164") == "+60123456789"
    assert value_of(result, "line_type") == "mobile"
    assert "MY" in value_of(result, "region")

    carrier = next(f for f in result.findings if f.entity_type == "carrier")
    # Number portability makes carrier data go stale, so it is deliberately not 1.0.
    assert carrier.confidence == 0.8
    assert all(f.confidence == 1.0 for f in result.findings if f.entity_type != "carrier")


async def test_local_format_uses_default_region():
    """A bare national number is parsed as Malaysian because MY is the default region."""
    seed = Seed(type=SeedType.phone, value="0123456789")
    result = await phone.run(seed, client=None)

    assert result.errors == []
    assert value_of(result, "e164") == "+60123456789"


async def test_valid_uk_number():
    seed = Seed(type=SeedType.phone, value="+442079460958")
    result = await phone.run(seed, client=None)

    assert result.errors == []
    assert value_of(result, "e164") == "+442079460958"
    assert value_of(result, "line_type") == "fixed_line"
    assert "GB" in value_of(result, "region")


async def test_invalid_number_yields_one_error_and_no_findings():
    seed = Seed(type=SeedType.phone, value="not-a-phone")
    result = await phone.run(seed, client=None)

    assert result.findings == []
    assert len(result.errors) == 1


async def test_parseable_but_invalid_number_is_rejected():
    seed = Seed(type=SeedType.phone, value="+60111")
    result = await phone.run(seed, client=None)

    assert result.findings == []
    assert len(result.errors) == 1
    assert "not a valid number" in result.errors[0]
