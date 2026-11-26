"""Confidence maths and the correlations that raise it. No network: avatars are served by respx."""

import io

import httpx
import pytest
import respx
from PIL import Image

from osint_agent.core import scoring
from osint_agent.core.scoring import (
    Profile,
    avatar_correlations,
    combine,
    decay,
    label,
    profile_of,
    static_correlations,
)


def image_bytes(kind: str, fmt: str = "PNG") -> bytes:
    """A deterministic 64x64 picture. 'gradient' and 'bars' are visibly different."""
    image = Image.new("L", (64, 64))
    if kind == "gradient":
        image.putdata([(x * 4 + y * 2) % 256 for y in range(64) for x in range(64)])
    else:
        image.putdata([255 if (x // 8) % 2 else 0 for y in range(64) for x in range(64)])
    if fmt == "JPEG":
        image = image.convert("RGB")
    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue()


def test_noisy_or_combines_independent_reporters():
    # 1 - (1-0.6)(1-0.6) = 0.84: two modules agreeing is worth more than either alone.
    assert combine({"social": 0.6, "username": 0.6}) == pytest.approx(0.84)
    assert combine({"social": 0.6}) == pytest.approx(0.6)
    assert combine({}) == pytest.approx(0.0)


def test_noisy_or_is_capped_so_nothing_is_ever_certain():
    everything = {f"module{n}": 0.9 for n in range(20)}

    assert combine(everything) == scoring.MAX_CONFIDENCE


def test_the_same_module_twice_is_not_independent_evidence():
    """The caller keys by module, so a second hit can only replace the first."""
    one_module = {"social": 0.6}
    one_module["social"] = max(one_module["social"], 0.6)

    assert combine(one_module) == pytest.approx(0.6)


def test_depth_decay_discounts_each_pivot():
    assert decay(1.0, 0) == pytest.approx(1.0)
    assert decay(1.0, 1) == pytest.approx(0.85)
    assert decay(1.0, 2) == pytest.approx(0.7225)
    assert decay(0.8, 2) == pytest.approx(0.578)


def test_labels_sit_on_the_documented_thresholds():
    assert label(0.99) == "strong"
    assert label(0.8) == "strong"
    assert label(0.79) == "likely"
    assert label(0.5) == "likely"
    assert label(0.49) == "possible"
    assert label(0.0) == "possible"


def test_a_bare_username_match_stays_possible_until_something_corroborates_it():
    bare = decay(combine({"username": 0.4}), 1)
    assert label(bare) == "possible"

    with_avatar = decay(combine({"username": 0.4, "correlation:same_avatar": 0.8}), 1)
    assert label(with_avatar) != "possible"


def test_profile_reads_avatar_display_name_and_link_domains():
    profile = profile_of(
        "account:github.com/jdoe",
        {
            "avatar_url": "https://img.test/a.png",
            "name": "Jane Doe",
            "blog": "jane.example.test",
            "bio": "writing at https://notes.example.test",
        },
    )

    assert profile.avatar_url == "https://img.test/a.png"
    assert profile.display_name == "jane doe"
    assert profile.link_domains == {"jane.example.test", "notes.example.test"}


def test_a_one_word_display_name_is_not_evidence():
    assert profile_of("account:a", {"name": "Jane"}).display_name is None
    assert profile_of("account:a", {"name": "Jane Doe"}).display_name == "jane doe"


def test_shared_links_and_names_raise_a_correlation():
    left = Profile(node_id="account:a", display_name="jane doe", link_domains={"jane.test"})
    right = Profile(node_id="account:b", display_name="jane doe", link_domains={"jane.test"})

    found = {c.relation: c for c in static_correlations([left, right])}

    assert found["shares_link"].confidence == scoring.SHARES_LINK
    assert found["same_display_name"].confidence == scoring.SAME_DISPLAY_NAME
    assert "jane.test" in found["shares_link"].evidence


def test_profiles_with_nothing_in_common_are_not_correlated():
    left = Profile(node_id="account:a", display_name="jane doe", link_domains={"jane.test"})
    right = Profile(node_id="account:b", display_name="john roe", link_domains={"john.test"})

    assert static_correlations([left, right]) == []


@respx.mock
async def test_the_same_avatar_re_encoded_still_matches(client):
    respx.get("https://img.test/a.png").mock(
        return_value=httpx.Response(200, content=image_bytes("gradient"))
    )
    respx.get("https://img.test/b.jpg").mock(
        return_value=httpx.Response(200, content=image_bytes("gradient", "JPEG"))
    )
    profiles = [
        Profile(node_id="account:a", avatar_url="https://img.test/a.png"),
        Profile(node_id="account:b", avatar_url="https://img.test/b.jpg"),
    ]

    found = await avatar_correlations(profiles, client)

    assert len(found) == 1
    assert found[0].relation == "same_avatar"
    assert found[0].confidence == scoring.SAME_AVATAR
    assert {found[0].a, found[0].b} == {"account:a", "account:b"}


@respx.mock
async def test_different_avatars_are_not_correlated(client):
    respx.get("https://img.test/a.png").mock(
        return_value=httpx.Response(200, content=image_bytes("gradient"))
    )
    respx.get("https://img.test/c.png").mock(
        return_value=httpx.Response(200, content=image_bytes("bars"))
    )
    profiles = [
        Profile(node_id="account:a", avatar_url="https://img.test/a.png"),
        Profile(node_id="account:c", avatar_url="https://img.test/c.png"),
    ]

    assert await avatar_correlations(profiles, client) == []


@respx.mock
async def test_an_oversized_or_missing_avatar_is_skipped_not_fatal(client, monkeypatch):
    monkeypatch.setattr(scoring, "MAX_AVATAR_BYTES", 10)
    respx.get("https://img.test/a.png").mock(
        return_value=httpx.Response(200, content=image_bytes("gradient"))
    )
    respx.get("https://img.test/gone.png").mock(return_value=httpx.Response(404))
    profiles = [
        Profile(node_id="account:a", avatar_url="https://img.test/a.png"),
        Profile(node_id="account:b", avatar_url="https://img.test/gone.png"),
    ]

    assert await avatar_correlations(profiles, client) == []


@respx.mock
async def test_avatar_downloads_are_capped_per_run(client, monkeypatch):
    monkeypatch.setattr(scoring, "MAX_AVATAR_DOWNLOADS", 2)
    routes = [
        respx.get(f"https://img.test/{n}.png").mock(
            return_value=httpx.Response(200, content=image_bytes("gradient"))
        )
        for n in range(5)
    ]
    profiles = [
        Profile(node_id=f"account:{n}", avatar_url=f"https://img.test/{n}.png") for n in range(5)
    ]

    await avatar_correlations(profiles, client)

    assert sum(route.called for route in routes) == 2


def test_unreadable_bytes_are_not_a_hash():
    assert scoring.phash_of(b"this is not an image") is None
    assert scoring.phash_of(image_bytes("bars")) is not None
