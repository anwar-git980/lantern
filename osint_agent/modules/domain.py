"""Domain and infrastructure enrichment: DNS, certificate transparency, RDAP, Shodan
InternetDB and the Wayback Machine.

The network sub-checks run concurrently and each reports its own failure, so crt.sh being slow
or down costs you only its subdomains. DNS runs first because the IP list feeds InternetDB.
"""

import asyncio
from urllib.parse import urlencode

import dns.asyncresolver
import dns.resolver
import httpx

from osint_agent.core.http import fetch_json
from osint_agent.core.models import Finding, ModuleResult, Seed, looks_like_hostname

NAME = "domain"
SUPPORTS = {"domain"}

DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
# A multi-homed box can list dead VPN or WSL resolvers ahead of the working one, and
# dnspython's default 5s lifetime expires mid-failover. Give the chain room at 2s per server.
DNS_SERVER_TIMEOUT = 2.0
DNS_TOTAL_TIMEOUT = 15.0

CRTSH_URL = "https://crt.sh/"
SLOW_TIMEOUT = 30.0  # crt.sh and the Wayback CDX API are both far slower than the client default
# shortcut: a busy domain can carry tens of thousands of certificate names. 500 characterises
# the attack surface; raise it when subdomain enumeration becomes its own module.
MAX_SUBDOMAINS = 500

RDAP_URL = "https://rdap.org/domain/{domain}"
RDAP_EVENTS = {"registration": "created", "expiration": "expires", "last changed": "last_changed"}

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
MAX_IPS = 10

WAYBACK_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_LIMIT = 1000
MAX_ARCHIVED_URLS = 20
INTERESTING_EXTENSIONS = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".sql",
    ".bak",
    ".env",
    ".zip",
    ".config",
)
INTERESTING_PATHS = ("admin", "login", "backup")


def _finding(entity_type: str, value: str, confidence: float, url: str | None = None, **raw):
    return Finding(
        module=NAME,
        entity_type=entity_type,
        value=value,
        source_url=url,
        confidence=confidence,
        raw=raw,
    )


async def resolve(name: str, rdtype: str) -> list[str]:
    """Record values as strings. Raises on lookup failure; the caller decides what that means."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_SERVER_TIMEOUT
    resolver.lifetime = DNS_TOTAL_TIMEOUT
    answers = await resolver.resolve(name, rdtype)
    if rdtype == "TXT":
        # A long TXT record arrives as several quoted chunks; join them before anyone reads it.
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
    if rdtype == "MX":
        # Keep the whole "preference exchange" text for the caller to split. Stripping the
        # trailing dot here would erase the lone dot that marks a null MX.
        return [r.to_text() for r in answers]
    return [r.to_text().rstrip(".") for r in answers]


async def _check_dns(domain: str) -> tuple[list[Finding], list[str]]:
    queries = [(rdtype, domain, rdtype) for rdtype in DNS_TYPES]
    queries.append(("DMARC", f"_dmarc.{domain}", "TXT"))

    outcomes = await asyncio.gather(
        *(resolve(qname, rdtype) for _, qname, rdtype in queries), return_exceptions=True
    )

    records: dict[str, list[str]] = {}
    errors: list[str] = []
    for (label, qname, rdtype), outcome in zip(queries, outcomes, strict=True):
        if isinstance(outcome, dns.resolver.NXDOMAIN):
            if label == "A":
                return [], [f"{domain} does not exist (NXDOMAIN)"]
            records[label] = []  # no _dmarc host is normal, and reported below as missing
        elif isinstance(outcome, dns.resolver.NoAnswer):
            records[label] = []
        elif isinstance(outcome, BaseException):
            records[label] = []
            errors.append(
                f"{rdtype} lookup for {qname} failed: {type(outcome).__name__}: {outcome}"
            )
        else:
            records[label] = outcome

    findings: list[Finding] = []
    for entity_type, label in (
        ("dns_a", "A"),
        ("dns_aaaa", "AAAA"),
        ("dns_ns", "NS"),
        ("dns_txt", "TXT"),
    ):
        findings += [_finding(entity_type, value, 1.0) for value in records.get(label, [])]

    for record in records.get("MX", []):
        preference, _, exchange = record.partition(" ")
        host = exchange.strip().rstrip(".")
        if not host:
            # RFC 7505 null MX: "0 ." is the domain stating it accepts no mail at all.
            findings.append(
                _finding("no_mx", f"{domain} publishes a null MX: it accepts no mail", 1.0)
            )
            continue
        findings.append(_finding("dns_mx", host, 1.0, preference=preference))

    findings.append(_mail_policy("spf", "v=spf1", records.get("TXT", []), domain))
    findings.append(_mail_policy("dmarc", "v=dmarc1", records.get("DMARC", []), domain))
    return findings, errors


def _mail_policy(kind: str, prefix: str, txt_records: list[str], domain: str) -> Finding:
    """A missing SPF or DMARC record is itself worth reporting: it is a spoofing exposure."""
    record = next((r for r in txt_records if r.lower().startswith(prefix)), None)
    if record:
        return _finding(kind, record, 1.0, present=True)
    return _finding(kind, f"{domain} publishes no {kind.upper()} record", 1.0, present=False)


async def _check_crtsh(domain: str, client: httpx.AsyncClient) -> tuple[list[Finding], list[str]]:
    params = {"q": f"%.{domain}", "output": "json"}
    source = f"{CRTSH_URL}?{urlencode(params)}"
    try:
        status, data = await fetch_json(client, CRTSH_URL, params=params, timeout=SLOW_TIMEOUT)
    except Exception as exc:
        return [], [f"crt.sh lookup failed: {type(exc).__name__}: {exc}"]

    if status != 200:
        return [], [f"crt.sh returned HTTP {status}"]
    if not isinstance(data, list):
        return [], ["crt.sh returned an unexpected body"]

    names = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for raw_name in (entry.get("name_value") or "").split("\n"):
            name = raw_name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith(f".{domain}"):
                names.add(name)

    errors = []
    if len(names) > MAX_SUBDOMAINS:
        errors.append(f"crt.sh: {len(names)} names found, reporting the first {MAX_SUBDOMAINS}")
    findings = [
        _finding("subdomain", name, 0.9, url=source) for name in sorted(names)[:MAX_SUBDOMAINS]
    ]
    return findings, errors


def _rdap_registrar(data: dict) -> str | None:
    """The registrar's name from its vCard.

    Contact entities are skipped deliberately: registrant personal data is not something this
    tool records, redacted or not.
    """
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray") or []
        fields = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        for field in fields:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                return str(field[3])
        if entity.get("handle"):
            return f"IANA registrar {entity['handle']}"
    return None


async def _check_rdap(domain: str, client: httpx.AsyncClient) -> tuple[list[Finding], list[str]]:
    url = RDAP_URL.format(domain=domain)
    try:
        status, data = await fetch_json(client, url)
    except Exception as exc:
        return [], [f"RDAP lookup failed: {type(exc).__name__}: {exc}"]

    if status == 404:
        return [], []  # not a registered domain, or no RDAP server for this TLD
    if status != 200 or not isinstance(data, dict):
        return [], [f"RDAP returned HTTP {status}"]

    findings = []
    registrar = _rdap_registrar(data)
    if registrar:
        findings.append(_finding("registrar", registrar, 1.0, url=url))

    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        entity_type = RDAP_EVENTS.get(event.get("eventAction", ""))
        if entity_type and event.get("eventDate"):
            findings.append(_finding(entity_type, str(event["eventDate"]), 1.0, url=url))

    for nameserver in data.get("nameservers") or []:
        if isinstance(nameserver, dict) and nameserver.get("ldhName"):
            name = str(nameserver["ldhName"]).lower().rstrip(".")
            findings.append(_finding("rdap_nameserver", name, 1.0, url=url))

    flags = [str(flag) for flag in data.get("status") or []]
    if flags:
        findings.append(_finding("domain_status", ", ".join(flags), 1.0, url=url))
    return findings, []


async def _check_internetdb(
    ips: list[str], client: httpx.AsyncClient
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    for ip in ips:
        url = INTERNETDB_URL.format(ip=ip)
        try:
            status, data = await fetch_json(client, url)
        except Exception as exc:
            errors.append(f"InternetDB lookup for {ip} failed: {type(exc).__name__}: {exc}")
            continue

        if status == 404:
            continue  # Shodan has nothing on this IP: a clean negative, not an error
        if status != 200 or not isinstance(data, dict):
            errors.append(f"InternetDB returned HTTP {status} for {ip}")
            continue

        cpes = [str(cpe) for cpe in data.get("cpes") or []]
        for port in data.get("ports") or []:
            # Shodan's scan data ages between sweeps, so this is strong but not certain.
            findings.append(
                _finding("open_port", f"{ip}:{port}", 0.8, url=url, ip=ip, port=port, cpes=cpes)
            )
        for cve in data.get("vulns") or []:
            findings.append(
                _finding(
                    "cve",
                    str(cve),
                    0.7,  # inferred from a banner's CPE, so worth verifying before acting
                    url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    ip=ip,
                )
            )
        for hostname in data.get("hostnames") or []:
            findings.append(_finding("reverse_hostname", str(hostname), 0.8, url=url, ip=ip))

    return findings, errors


def _day(timestamp: str) -> str:
    return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"


def _is_interesting(url: str) -> bool:
    path = url.lower().split("?")[0]
    return path.endswith(INTERESTING_EXTENSIONS) or any(p in path for p in INTERESTING_PATHS)


async def _check_wayback(domain: str, client: httpx.AsyncClient) -> tuple[list[Finding], list[str]]:
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original",
        "collapse": "urlkey",
        "limit": WAYBACK_LIMIT,
    }
    source = f"{WAYBACK_URL}?{urlencode(params)}"
    try:
        status, data = await fetch_json(client, WAYBACK_URL, params=params, timeout=SLOW_TIMEOUT)
    except Exception as exc:
        return [], [f"Wayback lookup failed: {type(exc).__name__}: {exc}"]

    if status != 200:
        return [], [f"Wayback returned HTTP {status}"]
    if not isinstance(data, list) or len(data) < 2:
        return [], []  # nothing archived: the CDX API returns a bare header row or nothing

    rows = [row for row in data[1:] if isinstance(row, list) and len(row) >= 2]
    timestamps = sorted(str(row[0]) for row in rows if row[0])
    span = f", {_day(timestamps[0])} to {_day(timestamps[-1])}" if timestamps else ""
    findings = [
        _finding(
            "archive_summary",
            f"{len(rows)} archived URLs{span}",
            1.0,
            url=source,
            captures=len(rows),
            first=timestamps[0] if timestamps else None,
            last=timestamps[-1] if timestamps else None,
        )
    ]

    for timestamp, original in ((str(row[0]), str(row[1])) for row in rows):
        if len(findings) > MAX_ARCHIVED_URLS:
            break
        if _is_interesting(original):
            findings.append(
                _finding(
                    "archived_url",
                    original,
                    0.6,
                    url=f"https://web.archive.org/web/{timestamp}/{original}",
                    timestamp=timestamp,
                )
            )
    return findings, []


async def run(seed: Seed, client: httpx.AsyncClient) -> ModuleResult:
    result = ModuleResult(module=NAME)
    domain = seed.normalized

    if not looks_like_hostname(domain):
        result.errors.append(f"{seed.value!r} does not look like a domain name")
        return result

    dns_findings, dns_errors = await _check_dns(domain)
    result.findings.extend(dns_findings)
    result.errors.extend(dns_errors)

    ips = list(dict.fromkeys(f.value for f in dns_findings if f.entity_type == "dns_a"))[:MAX_IPS]

    outcomes = await asyncio.gather(
        _check_crtsh(domain, client),
        _check_rdap(domain, client),
        _check_internetdb(ips, client),
        _check_wayback(domain, client),
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
