"""Pulls new investigable identifiers out of findings: the pivot step of the agent loop.

Every string read here came from the internet (a bio, a search snippet, an archived URL), so
extraction is deliberately conservative. A wrong pivot spends a module run on a stranger, and
in the LLM loop it also puts an attacker's chosen value in front of the model.
"""

import re
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel

from osint_agent.core.models import Finding, Seed, SeedType, looks_like_hostname

EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9][a-z0-9.\-]*\.[a-z]{2,63}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
# 2-39 characters, starting alphanumeric, and it must contain a letter so that bare ids and
# years ("123456", "2024") are never mistaken for handles.
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,38}$", re.IGNORECASE)

# Only these findings describe a person or something they own. Everything else - DNS records,
# certificate names, open ports, breach metadata, holehe service hits - is infrastructure or a
# third party: pivoting on a shared mail server investigates the hosting provider, and one busy
# domain's certificate names would swamp the frontier on their own.
PIVOTABLE_TYPES = frozenset(
    {"account", "linked_account", "linked_url", "avatar", "dork_hit", "archived_url"}
)

# Hosts we queried ourselves, search engines, and platforms so large that a link to one says
# nothing about the subject. Matched against the host and any subdomain of it.
IGNORED_DOMAINS = frozenset(
    {
        # our own sources
        "haveibeenpwned.com",
        "crt.sh",
        "archive.org",
        "web.archive.org",
        "gravatar.com",
        "github.com",
        "shodan.io",
        "rdap.org",
        "nvd.nist.gov",
        "algolia.com",
        "news.ycombinator.com",
        "bsky.app",
        "bsky.social",
        "reddit.com",
        "redd.it",
        # search engines
        "google.com",
        "bing.com",
        "duckduckgo.com",
        "yahoo.com",
        "yandex.com",
        "baidu.com",
        "brave.com",
        # big platforms: shared space, never the subject's own
        "facebook.com",
        "linkedin.com",
        "youtube.com",
        "youtu.be",
        "twitter.com",
        "x.com",
        "instagram.com",
        "tiktok.com",
        "pinterest.com",
        "medium.com",
        "wikipedia.org",
        "gitlab.com",
        "bitbucket.org",
        "stackoverflow.com",
        "mastodon.social",
        "t.me",
        "wa.me",
        "gmail.com",
        "googleusercontent.com",
        "githubusercontent.com",
        "gstatic.com",
        "cloudfront.net",
        "akamaized.net",
        "fbcdn.net",
        "twimg.com",
        "licdn.com",
        "imgur.com",
        "gettyimages.com",
        "apple.com",
        "microsoft.com",
        "amazon.com",
        "cloudflare.com",
        "w3.org",
        "schema.org",
        "bit.ly",
        "goo.gl",
    }
)

# Single-segment paths on the profile hosts below that are site furniture, not an account.
RESERVED_PATHS = frozenset(
    {
        "about",
        "collections",
        "explore",
        "features",
        "home",
        "i",
        "intent",
        "join",
        "login",
        "logout",
        "marketplace",
        "new",
        "notifications",
        "orgs",
        "pricing",
        "search",
        "security",
        "settings",
        "share",
        "signup",
        "sponsors",
        "topics",
        "trending",
    }
)

# A bare hostname is only trusted in a field defined to hold one.
HOST_FIELDS = frozenset({"blog", "website", "url", "domain"})

# An `account` finding names a profile ON a platform, and an `avatar` names a CDN. The host in
# those URLs belongs to the platform, never to the subject, so taking a domain seed from one
# sends the next hop at Discord's subdomains instead of at the person. The handle inside the
# same URL is still a good pivot, and a domain the subject published themselves still arrives
# via `linked_url` or a `blog` field.
PLATFORM_URL_TYPES = frozenset({"account", "avatar", "registered_service"})
PLATFORM_URL_FIELDS = frozenset({"value", "source_url", "url_main", "url_user", "profileUrl"})

# Free-text fields: prose the subject (or an attacker) typed. An identifier found only here
# is still recorded, but it does not become something the agent may act on - see
# Candidate.from_prose. A `dork_hit` value is a page title, so it counts as prose too.
PROSE_FIELDS = frozenset(
    {
        "about",
        "bio",
        "company",
        "description",
        "location",
        "public_description",
        "snippet",
        "title",
    }
)


class Candidate(BaseModel):
    """A new seed plus the finding it came out of, so the graph can draw the edge that
    justifies investigating it and the agent loop can show the model where it came from."""

    seed: Seed
    module: str
    entity_type: str
    found_in: str
    source_url: str | None = None
    # The graph node of the finding this came out of, so the edge starts at the evidence
    # rather than at the seed we happened to be investigating.
    found_node: str = ""
    # True when the only place this identifier appeared was prose someone wrote: a bio, a
    # search snippet, a page title. It is recorded in the graph, but the agent loop keeps it
    # out of the frontier, so text from the internet can never nominate the next target.
    from_prose: bool = False

    @property
    def node_id(self) -> str:
        return f"{self.seed.type.value}:{self.seed.normalized}"


def is_ignored_host(host: str) -> bool:
    host = host.lower().removeprefix("www.").strip(".")
    return any(host == domain or host.endswith(f".{domain}") for domain in IGNORED_DOMAINS)


def _looks_like_username(value: str) -> bool:
    return bool(USERNAME_RE.match(value)) and any(char.isalpha() for char in value)


def _username_from_url(url: str) -> str | None:
    """The handle a known profile URL names, or None when the URL is not a profile page."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    parts = [part for part in parsed.path.split("/") if part]

    if host == "news.ycombinator.com":
        ids = parse_qs(parsed.query).get("id")
        return ids[0] if ids else None
    if host in ("github.com", "x.com", "twitter.com"):
        # Two segments is a repository or a status, not an account.
        if len(parts) == 1 and parts[0].lower() not in RESERVED_PATHS:
            return parts[0]
        return None
    if host == "reddit.com" and len(parts) == 2 and parts[0] in ("user", "u"):
        return parts[1]
    if host == "bsky.app" and len(parts) == 2 and parts[0] == "profile":
        return parts[1]
    return None


def _domain_of(url: str) -> str | None:
    host = (urlparse(url).hostname or "").lower().removeprefix("www.").strip(".")
    if not host or not looks_like_hostname(host) or is_ignored_host(host):
        return None
    return host


def _fields(finding: Finding) -> list[tuple[str, str]]:
    """Every (field name, text) pair worth scanning on one finding."""
    fields = [("value", finding.value)]
    if finding.source_url:
        fields.append(("source_url", finding.source_url))
    fields += [(key, text) for key, text in finding.raw.items() if isinstance(text, str) and text]
    return fields


def _is_platform_url(finding: Finding, field: str) -> bool:
    return finding.entity_type in PLATFORM_URL_TYPES and field in PLATFORM_URL_FIELDS


def _is_prose(finding: Finding, field: str) -> bool:
    if field in PROSE_FIELDS:
        return True
    # A dork hit's value is the result title, which is whatever the page author wrote.
    return finding.entity_type == "dork_hit" and field == "value"


def _candidates(finding: Finding) -> list[Candidate]:
    def make(seed_type: SeedType, value: str, field: str) -> Candidate:
        return Candidate(
            seed=Seed(type=seed_type, value=value),
            module=finding.module,
            entity_type=finding.entity_type,
            found_in=f"{finding.entity_type} ({field})",
            source_url=finding.source_url,
            found_node=f"{finding.entity_type}:{finding.value}",
            from_prose=_is_prose(finding, field),
        )

    out: list[Candidate] = []

    # A linked_account finding has already parsed the handle out for us.
    handle = finding.raw.get("username")
    if (
        finding.entity_type == "linked_account"
        and isinstance(handle, str)
        and _looks_like_username(handle)
    ):
        out.append(make(SeedType.username, handle, "username"))

    for field, text in _fields(finding):
        for email in EMAIL_RE.findall(text):
            if not is_ignored_host(email.partition("@")[2]):
                out.append(make(SeedType.email, email, field))

        urls = URL_RE.findall(text)
        # "github.com/jdoe" in a value field is a profile path that lost its scheme.
        if field == "value" and not urls and "/" in text and " " not in text:
            urls = [f"https://{text.lstrip('/')}"]

        for raw_url in urls:
            url = raw_url.rstrip(".,);")
            username = _username_from_url(url)
            if username and _looks_like_username(username):
                out.append(make(SeedType.username, username, field))
                continue
            if _is_platform_url(finding, field):
                continue
            domain = _domain_of(url)
            if domain:
                out.append(make(SeedType.domain, domain, field))

        if (
            field in HOST_FIELDS
            and not urls
            and looks_like_hostname(text.lower())
            and not is_ignored_host(text)
        ):
            out.append(make(SeedType.domain, text.lower(), field))

    return out


def extract_seeds(findings: list[Finding], parent: Seed | None = None) -> list[Candidate]:
    """New identifiers worth investigating, deduped, with noise and the parent seed dropped.

    shortcut: phone numbers are never extracted from free text. A digit run in a bio or a
    search snippet is far more often an order number, a date or a version than a phone
    number. Revisit when a module starts reporting a phone number as a structured field.
    """
    blocked = {parent.normalized, f"{parent.type.value}:{parent.normalized}"} if parent else set()
    found: dict[str, Candidate] = {}

    for finding in findings:
        if finding.entity_type not in PIVOTABLE_TYPES:
            continue
        for candidate in _candidates(finding):
            key = candidate.node_id
            if key in blocked or candidate.seed.normalized in blocked:
                continue
            previous = found.get(key)
            if previous is None:
                found[key] = candidate
            elif previous.from_prose and not candidate.from_prose:
                # Seen in prose first, now seen in a structured field: the structured
                # sighting is the stronger one, so it wins.
                found[key] = candidate

    return list(found.values())
