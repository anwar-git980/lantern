"""Confidence maths and the correlations that raise it.

A module's own confidence says how sure *it* is. This module answers the different question the
graph needs: how sure are we that a node is real and belongs to the subject, given everything
that reported it. Independent agreement raises confidence; distance from the seed lowers it.
"""

import io
import logging

import httpx
import imagehash
from PIL import Image
from pydantic import BaseModel

from osint_agent.core.extract import URL_RE, is_ignored_host
from osint_agent.core.http import fetch_bytes

logger = logging.getLogger("osint_agent.scoring")

MAX_CONFIDENCE = 0.99
DEPTH_DECAY = 0.85
STRONG = 0.8
LIKELY = 0.5

SAME_AVATAR = 0.8
SHARES_LINK = 0.7
SAME_DISPLAY_NAME = 0.4
# Two perceptual hashes within this Hamming distance are the same picture, allowing for the
# re-encoding and rescaling every platform does to an uploaded avatar.
PHASH_MAX_DISTANCE = 6
MAX_AVATAR_DOWNLOADS = 20
MAX_AVATAR_BYTES = 1_000_000

AVATAR_KEYS = ("avatar_url", "avatar", "icon_img", "thumbnailUrl")
NAME_KEYS = ("name", "display_name", "displayName")
# Fields whose text is free-form enough to hold a link the profile owner chose to publish.
LINK_KEYS = ("blog", "bio", "description", "about", "website")


class Correlation(BaseModel):
    """Evidence that two account nodes are probably the same person."""

    a: str
    b: str
    relation: str
    confidence: float
    evidence: str


class Profile(BaseModel):
    """The correlatable attributes of one account finding."""

    node_id: str
    avatar_url: str | None = None
    display_name: str | None = None
    link_domains: set[str] = set()


def combine(by_module: dict[str, float]) -> float:
    """Noisy-OR across independent reporters: 1 - prod(1 - c).

    The caller keys the input by module, so two hits from the same module count once. Two
    modules agreeing is real evidence; one module saying the same thing twice is not.
    """
    product = 1.0
    for confidence in by_module.values():
        product *= 1.0 - confidence
    return min(round(1.0 - product, 6), MAX_CONFIDENCE)


def decay(confidence: float, depth: int) -> float:
    """Confidence drops with each pivot: a hop away from the seed is a hop of inference."""
    return round(confidence * DEPTH_DECAY**depth, 6)


def label(confidence: float) -> str:
    if confidence >= STRONG:
        return "strong"
    if confidence >= LIKELY:
        return "likely"
    return "possible"


def _first_string(raw: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _link_domains(raw: dict) -> set[str]:
    domains: set[str] = set()
    for key in LINK_KEYS:
        text = raw.get(key)
        if not isinstance(text, str) or not text:
            continue
        urls = URL_RE.findall(text)
        if not urls and key in ("blog", "website") and "." in text and " " not in text:
            urls = [f"https://{text}"]
        for url in urls:
            host = (httpx.URL(url.rstrip(".,);")).host or "").lower().removeprefix("www.")
            if host and not is_ignored_host(host):
                domains.add(host)
    return domains


def profile_of(node_id: str, raw: dict) -> Profile:
    name = _first_string(raw, NAME_KEYS)
    # A single word ("Jane", a handle repeated as a name) collides far too easily to be
    # evidence of anything.
    if name and len(name.split()) < 2:
        name = None
    return Profile(
        node_id=node_id,
        avatar_url=_first_string(raw, AVATAR_KEYS),
        display_name=name.lower() if name else None,
        link_domains=_link_domains(raw),
    )


def _pairs(profiles: list[Profile]):
    for index, left in enumerate(profiles):
        for right in profiles[index + 1 :]:
            yield left, right


def static_correlations(profiles: list[Profile]) -> list[Correlation]:
    """Shared links and display names: everything decidable without a network call."""
    out: list[Correlation] = []
    for left, right in _pairs(profiles):
        shared = left.link_domains & right.link_domains
        if shared:
            out.append(
                Correlation(
                    a=left.node_id,
                    b=right.node_id,
                    relation="shares_link",
                    confidence=SHARES_LINK,
                    evidence=f"both link to {', '.join(sorted(shared))}",
                )
            )
        if left.display_name and left.display_name == right.display_name:
            out.append(
                Correlation(
                    a=left.node_id,
                    b=right.node_id,
                    relation="same_display_name",
                    confidence=SAME_DISPLAY_NAME,
                    evidence=f"both display {left.display_name!r}",
                )
            )
    return out


def phash_of(data: bytes) -> imagehash.ImageHash | None:
    """The perceptual hash of an image, or None when the bytes are not a readable image."""
    try:
        with Image.open(io.BytesIO(data)) as image:
            return imagehash.phash(image)
    except Exception:
        return None


async def avatar_correlations(
    profiles: list[Profile], client: httpx.AsyncClient
) -> list[Correlation]:
    """Download each distinct avatar once and pair up the ones that are the same picture."""
    wanted = [profile for profile in profiles if profile.avatar_url]
    hashes: dict[str, imagehash.ImageHash] = {}
    seen_urls: dict[str, imagehash.ImageHash | None] = {}

    for profile in wanted[:MAX_AVATAR_DOWNLOADS]:
        url = profile.avatar_url or ""
        if url not in seen_urls:
            try:
                data = await fetch_bytes(client, url, max_bytes=MAX_AVATAR_BYTES)
            except Exception as exc:
                logger.debug("avatar fetch failed %s: %s", url, exc)
                data = None
            seen_urls[url] = phash_of(data) if data else None
        digest = seen_urls[url]
        if digest is not None:
            hashes[profile.node_id] = digest

    out: list[Correlation] = []
    nodes = sorted(hashes)
    for index, left in enumerate(nodes):
        for right in nodes[index + 1 :]:
            distance = hashes[left] - hashes[right]
            if distance <= PHASH_MAX_DISTANCE:
                out.append(
                    Correlation(
                        a=left,
                        b=right,
                        relation="same_avatar",
                        confidence=SAME_AVATAR,
                        evidence=f"avatar phash distance {distance}",
                    )
                )
    return out
