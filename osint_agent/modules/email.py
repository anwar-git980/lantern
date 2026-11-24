"""Email enrichment: MX records, HIBP breach metadata, Gravatar profile, holehe registrations.

Every sub-check runs concurrently and reports its own failure rather than raising, so one
dead service never costs you the other three.
"""

import asyncio
import hashlib
import importlib
import logging
import os
import pkgutil
from urllib.parse import quote

import dns.asyncresolver
import dns.resolver
import httpx

from osint_agent.core.models import Finding, ModuleResult, Seed

NAME = "email"
SUPPORTS = {"email"}

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_SOURCE = "https://haveibeenpwned.com/"
# Deliberately metadata-only: no password, hash or dump content is ever read or stored.
HIBP_RAW_KEYS = ("BreachDate", "DataClasses", "PwnCount", "Domain")
GRAVATAR_URL = "https://gravatar.com/{digest}.json"
MX_SERVER_TIMEOUT = 2.0
MX_TOTAL_TIMEOUT = 15.0
HOLEHE_CLIENT_TIMEOUT = 10.0
# Unbounded, holehe's ~120 checks fan out at once and exhaust the DNS resolver, which starves
# the MX and Gravatar checks running alongside them. Observed in testing; hence the cap.
HOLEHE_CONCURRENCY = 16
# shortcut: one wall-clock cap for all ~120 holehe checks, not per-site. Revisit if a slow
# site starves the rest - then move to per-module timeouts.
HOLEHE_TOTAL_TIMEOUT = 90.0


def _finding(entity_type: str, value: str, confidence: float, url: str | None = None, **raw):
    return Finding(
        module=NAME,
        entity_type=entity_type,
        value=value,
        source_url=url,
        confidence=confidence,
        raw=raw,
    )


def _syntax_error(email: str) -> str | None:
    if email.count("@") != 1:
        return f"{email!r} is not a syntactically valid email address"
    local, _, domain = email.partition("@")
    if not local or not domain or "." not in domain or domain.startswith("."):
        return f"{email!r} is not a syntactically valid email address"
    return None


async def _check_mx(email: str) -> tuple[list[Finding], list[str]]:
    domain = email.partition("@")[2]
    # A multi-homed box (VPN or WSL adapters) can list several dead resolvers ahead of the
    # working one. dnspython's default 5s lifetime expires mid-failover, so give the whole
    # chain room to fall through at 2s per server.
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = MX_SERVER_TIMEOUT
    resolver.lifetime = MX_TOTAL_TIMEOUT
    try:
        answers = await resolver.resolve(domain, "MX")
    except dns.resolver.NXDOMAIN:
        return [], [f"domain {domain} does not exist (NXDOMAIN)"]
    except dns.resolver.NoAnswer:
        return [
            _finding("no_mx", f"{domain} publishes no MX records (does not accept mail)", 1.0)
        ], []
    except Exception as exc:
        return [], [f"MX lookup for {domain} failed: {type(exc).__name__}: {exc}"]

    findings = [
        _finding(
            "mx",
            str(rdata.exchange).rstrip("."),
            1.0,
            preference=rdata.preference,
            domain=domain,
        )
        for rdata in sorted(answers, key=lambda r: r.preference)
    ]
    return findings, []


async def _check_hibp(email: str, client: httpx.AsyncClient) -> tuple[list[Finding], list[str]]:
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return [], ["HIBP_API_KEY not set - breach check skipped"]

    url = HIBP_URL.format(email=quote(email, safe=""))
    headers = {"hibp-api-key": api_key, "user-agent": "osint-agent"}
    params = {"truncateResponse": "false"}

    response = await client.get(url, headers=headers, params=params)
    if response.status_code == 429:
        retry_after = response.headers.get("retry-after", "2")
        try:
            delay = min(float(retry_after), 30.0)
        except ValueError:
            delay = 2.0
        await asyncio.sleep(delay)
        response = await client.get(url, headers=headers, params=params)

    if response.status_code == 404:
        return [], []  # not breached: a clean negative, not an error
    if response.status_code == 429:
        return [], ["HIBP rate limited after one retry - breach check incomplete"]
    if response.status_code != 200:
        return [], [f"HIBP returned HTTP {response.status_code}"]

    findings = [
        _finding(
            "breach",
            breach.get("Name", "unknown"),
            1.0,
            url=HIBP_SOURCE,
            **{key: breach.get(key) for key in HIBP_RAW_KEYS},
        )
        for breach in response.json()
    ]
    return findings, []


async def _check_gravatar(email: str, client: httpx.AsyncClient) -> tuple[list[Finding], list[str]]:
    digest = hashlib.sha256(email.encode()).hexdigest()
    url = GRAVATAR_URL.format(digest=digest)

    try:
        response = await client.get(url)
    except Exception as exc:
        return [], [f"Gravatar lookup failed: {type(exc).__name__}: {exc}"]

    if response.status_code == 404:
        return [], []
    if response.status_code != 200:
        return [], [f"Gravatar returned HTTP {response.status_code}"]

    try:
        entries = response.json().get("entry") or []
    except ValueError:
        return [], ["Gravatar returned a non-JSON body"]
    if not entries:
        return [], []

    entry = entries[0]
    profile_url = entry.get("profileUrl")
    findings = []

    avatar = entry.get("thumbnailUrl") or profile_url
    if avatar:
        findings.append(_finding("avatar", avatar, 1.0, url=profile_url, hash=entry.get("hash")))

    for account in entry.get("accounts") or []:
        label = account.get("display") or account.get("username") or account.get("domain")
        if label:
            domain = account.get("domain") or "?"
            findings.append(
                _finding(
                    "account",
                    f"{domain}: {label}",
                    0.9,
                    url=account.get("url"),
                    domain=account.get("domain"),
                )
            )

    for link in entry.get("urls") or []:
        value = link.get("title") or link.get("value")
        if value:
            findings.append(_finding("account", value, 0.9, url=link.get("value")))

    return findings, []


def _holehe_checks() -> list:
    """Every leaf holehe module exposes one coroutine named after its own file."""
    import holehe.modules as holehe_modules

    checks = []
    for info in pkgutil.walk_packages(holehe_modules.__path__, "holehe.modules."):
        if info.ispkg:
            continue
        try:
            module = importlib.import_module(info.name)
        except Exception:
            continue
        func = getattr(module, info.name.rsplit(".", 1)[1], None)
        if asyncio.iscoroutinefunction(func):
            checks.append(func)
    return checks


async def _check_holehe(email: str) -> tuple[list[Finding], list[str]]:
    from holehe.core import launch_module

    # holehe parses responses with BeautifulSoup, which logs a decode warning on pages with
    # mixed encoding. That is upstream noise, not a finding, so keep it out of our output.
    logging.getLogger("bs4.dammit").setLevel(logging.ERROR)

    checks = _holehe_checks()
    if not checks:
        return [], ["holehe exposed no usable modules"]

    out: list[dict] = []

    # holehe's modules infer existence from redirect behaviour, so they get their own client
    # with httpx defaults rather than the runner's follow_redirects=True one.
    async with httpx.AsyncClient(timeout=HOLEHE_CLIENT_TIMEOUT) as client:
        limit = asyncio.Semaphore(HOLEHE_CONCURRENCY)

        async def guarded(func):
            # launch_module has its own except branch, but it looks the module up in a
            # hardcoded name map and KeyErrors on anything missing from it.
            async with limit:
                try:
                    await launch_module(func, email, client, out)
                except Exception:
                    pass

        try:
            await asyncio.wait_for(
                asyncio.gather(*(guarded(f) for f in checks)), HOLEHE_TOTAL_TIMEOUT
            )
        except TimeoutError:
            pass

    findings = [
        _finding(
            "registered_service",
            entry.get("domain") or entry.get("name", "unknown"),
            0.7,
            name=entry.get("name"),
        )
        for entry in out
        if entry.get("exists")
    ]

    skipped = sum(1 for e in out if e.get("rateLimit")) + max(0, len(checks) - len(out))
    errors = []
    if skipped:
        errors.append(
            f"holehe: {skipped} of {len(checks)} checks skipped (errored or rate limited)"
        )
    return findings, errors


async def run(seed: Seed, client: httpx.AsyncClient) -> ModuleResult:
    result = ModuleResult(module=NAME)
    email = seed.normalized

    syntax_error = _syntax_error(email)
    if syntax_error:
        result.errors.append(syntax_error)
        return result

    outcomes = await asyncio.gather(
        _check_mx(email),
        _check_hibp(email, client),
        _check_gravatar(email, client),
        _check_holehe(email),
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
