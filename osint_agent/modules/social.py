"""Public profile lookups for a username: GitHub, Reddit, Bluesky, Hacker News, Mastodon.

Every endpoint is a documented public API, reachable without logging in. Sub-checks run
concurrently and each reports its own failure. Links found in a bio become linked_url or
linked_account findings: those are the pivot points a follow-up investigation starts from.
"""

import asyncio
import html
import os
import re
from datetime import UTC, datetime

import httpx

from osint_agent.core.http import fetch_json
from osint_agent.core.models import Finding, ModuleResult, Seed, looks_like_hostname

NAME = "social"
SUPPORTS = {"username"}

GITHUB_URL = "https://api.github.com/users/{username}"
GITHUB_FIELDS = (
    "name",
    "avatar_url",
    "bio",
    "blog",
    "location",
    "company",
    "public_repos",
    "created_at",
    "twitter_username",
)
REDDIT_URL = "https://www.reddit.com/user/{username}/about.json"
BLUESKY_URL = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
HN_URL = "https://hn.algolia.com/api/v1/users/{username}"
WEBFINGER_URL = "https://{instance}/.well-known/webfinger"

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
TAG_RE = re.compile(r"<[^>]+>")
TTL = 43200.0  # 12h: a bio changes, but not minute to minute


def _finding(entity_type: str, value: str, confidence: float, url: str | None = None, **raw):
    return Finding(
        module=NAME,
        entity_type=entity_type,
        value=value,
        source_url=url,
        confidence=confidence,
        raw=raw,
    )


def _links_from(text: str | None, source: str) -> list[Finding]:
    """Every URL mentioned in a bio, deduped. Low confidence: a mention is not ownership."""
    if not text:
        return []
    urls = dict.fromkeys(url.rstrip(".,);") for url in URL_RE.findall(text))
    return [_finding("linked_url", url, 0.5, url=url, found_in=source) for url in urls]


def _epoch_day(value) -> str | None:
    try:
        return datetime.fromtimestamp(float(value), UTC).date().isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _plain_text(markup: str | None) -> str | None:
    """Hacker News returns HTML in its about field; keep the words, drop the tags."""
    if not markup:
        return None
    return " ".join(html.unescape(TAG_RE.sub(" ", markup)).split()) or None


async def _check_github(
    username: str, client: httpx.AsyncClient
) -> tuple[list[Finding], list[str]]:
    url = GITHUB_URL.format(username=username)
    headers = {"accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["authorization"] = f"Bearer {token}"

    try:
        status, data = await fetch_json(client, url, headers=headers, ttl=TTL)
    except Exception as exc:
        return [], [f"GitHub lookup failed: {type(exc).__name__}: {exc}"]

    if status == 404:
        return [], []
    if status in (403, 429):
        return [], ["GitHub rate limited - set GITHUB_TOKEN to raise the limit"]
    if status != 200 or not isinstance(data, dict):
        return [], [f"GitHub returned HTTP {status}"]

    login = data.get("login") or username
    profile = data.get("html_url") or f"https://github.com/{login}"
    findings = [
        _finding(
            "account",
            f"github.com/{login}",
            0.6,
            url=profile,
            **{field: data.get(field) for field in GITHUB_FIELDS},
        )
    ]

    blog = (data.get("blog") or "").strip()
    if blog:
        target = blog if blog.startswith(("http://", "https://")) else f"https://{blog}"
        findings.append(_finding("linked_url", target, 0.7, url=target, found_in="github blog"))

    twitter = (data.get("twitter_username") or "").strip()
    if twitter:
        findings.append(
            _finding(
                "linked_account",
                f"twitter.com/{twitter}",
                0.7,
                url=f"https://twitter.com/{twitter}",
                found_in="github profile",
                username=twitter,
            )
        )

    findings += _links_from(data.get("bio"), "github bio")
    return findings, []


async def _check_reddit(
    username: str, client: httpx.AsyncClient
) -> tuple[list[Finding], list[str]]:
    url = REDDIT_URL.format(username=username)
    try:
        status, data = await fetch_json(client, url, ttl=TTL)
    except Exception as exc:
        return [], [f"Reddit lookup failed: {type(exc).__name__}: {exc}"]

    if status == 404:
        return [], []
    if status in (403, 429):
        return [], [f"Reddit returned HTTP {status} - it throttles unauthenticated clients hard"]
    if status != 200 or not isinstance(data, dict):
        return [], [f"Reddit returned HTTP {status}"]

    profile = data.get("data") or {}
    if not profile:
        return [], []

    name = profile.get("name") or username
    findings = [
        _finding(
            "account",
            f"reddit.com/user/{name}",
            0.6,
            url=f"https://www.reddit.com/user/{name}",
            link_karma=profile.get("link_karma"),
            comment_karma=profile.get("comment_karma"),
            total_karma=profile.get("total_karma"),
            created=_epoch_day(profile.get("created_utc")),
            verified=profile.get("verified"),
            icon_img=profile.get("icon_img"),
        )
    ]
    findings += _links_from(
        (profile.get("subreddit") or {}).get("public_description"), "reddit bio"
    )
    return findings, []


async def _check_bluesky(
    username: str, client: httpx.AsyncClient
) -> tuple[list[Finding], list[str]]:
    # A handle containing a dot is already fully qualified (a custom domain).
    actor = username if "." in username else f"{username}.bsky.social"
    try:
        status, data = await fetch_json(client, BLUESKY_URL, params={"actor": actor}, ttl=TTL)
    except Exception as exc:
        return [], [f"Bluesky lookup failed: {type(exc).__name__}: {exc}"]

    if status in (400, 404):
        return [], []  # Bluesky answers 400 InvalidRequest for a handle that does not resolve
    if status != 200 or not isinstance(data, dict):
        return [], [f"Bluesky returned HTTP {status}"]

    handle = data.get("handle") or actor
    findings = [
        _finding(
            "account",
            f"bsky.app/profile/{handle}",
            0.6,
            url=f"https://bsky.app/profile/{handle}",
            display_name=data.get("displayName"),
            avatar=data.get("avatar"),
            description=data.get("description"),
            followers=data.get("followersCount"),
            follows=data.get("followsCount"),
            posts=data.get("postsCount"),
            created=data.get("createdAt"),
            did=data.get("did"),
        )
    ]
    findings += _links_from(data.get("description"), "bluesky bio")
    return findings, []


async def _check_hackernews(
    username: str, client: httpx.AsyncClient
) -> tuple[list[Finding], list[str]]:
    url = HN_URL.format(username=username)
    try:
        status, data = await fetch_json(client, url, ttl=TTL)
    except Exception as exc:
        return [], [f"Hacker News lookup failed: {type(exc).__name__}: {exc}"]

    # Algolia answers 500, not 404, for a username it has never seen. Verified against a known
    # user, which returns 200. Treating 500 as an error would mean a permanent false warning on
    # every seed that simply has no Hacker News account.
    if status in (404, 500):
        return [], []
    if status != 200 or not isinstance(data, dict):
        return [], [f"Hacker News returned HTTP {status}"]
    if not data.get("username"):
        return [], []

    name = data["username"]
    findings = [
        _finding(
            "account",
            f"news.ycombinator.com/user?id={name}",
            0.6,
            url=f"https://news.ycombinator.com/user?id={name}",
            karma=data.get("karma"),
            created=data.get("created_at"),
            about=_plain_text(data.get("about")),
        )
    ]
    findings += _links_from(data.get("about"), "hacker news about")
    return findings, []


async def _check_mastodon(
    username: str, client: httpx.AsyncClient
) -> tuple[list[Finding], list[str]]:
    # Only a user@instance handle names an instance to ask. A plain username does not, and
    # guessing instances would mean spraying servers that never heard of this person.
    if username.count("@") != 1:
        return [], []
    user, _, instance = username.partition("@")
    if not user or not looks_like_hostname(instance):
        return [], []

    url = WEBFINGER_URL.format(instance=instance)
    params = {"resource": f"acct:{user}@{instance}"}
    try:
        status, data = await fetch_json(client, url, params=params, ttl=TTL)
    except Exception as exc:
        return [], [f"WebFinger on {instance} failed: {type(exc).__name__}: {exc}"]

    if status in (404, 410):
        return [], []
    if status != 200 or not isinstance(data, dict):
        return [], [f"WebFinger on {instance} returned HTTP {status}"]

    links = [link for link in data.get("links") or [] if isinstance(link, dict)]
    profile = next(
        (
            link.get("href")
            for link in links
            if link.get("rel") == "http://webfinger.net/rel/profile-page"
        ),
        None,
    )
    subject = str(data.get("subject") or f"acct:{user}@{instance}").removeprefix("acct:")
    return [
        _finding(
            "account",
            subject,
            0.6,
            url=profile,
            instance=instance,
            aliases=[alias for alias in data.get("aliases") or [] if isinstance(alias, str)],
        )
    ], []


async def run(seed: Seed, client: httpx.AsyncClient) -> ModuleResult:
    result = ModuleResult(module=NAME)
    username = seed.normalized

    outcomes = await asyncio.gather(
        _check_github(username, client),
        _check_reddit(username, client),
        _check_bluesky(username, client),
        _check_hackernews(username, client),
        _check_mastodon(username, client),
        return_exceptions=True,
    )
    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            result.errors.append(f"sub-check failed: {type(outcome).__name__}: {outcome}")
            continue
        findings, errors = outcome
        result.findings.extend(findings)
        result.errors.extend(errors)

    return result
