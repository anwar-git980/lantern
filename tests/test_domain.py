"""Domain module tests. All HTTP is mocked with respx and DNS is faked at our own resolver."""

import json

import dns.resolver
import httpx
import respx

from osint_agent.modules import domain as domain_module
from osint_agent.modules.domain import (
    _check_crtsh,
    _check_dns,
    _check_internetdb,
    _check_rdap,
    _check_wayback,
)

DOMAIN = "example.test"

DNS_ANSWERS = {
    "A": ["93.184.216.34", "93.184.216.34"],
    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "MX": ["10 mail.example.test", "20 backup.example.test"],
    "NS": ["a.iana-servers.net", "b.iana-servers.net"],
    "TXT": ["v=spf1 include:_spf.example.test -all", "docusign=abc123"],
}

RDAP_BODY = {
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:38Z"},
        {"eventAction": "last update of RDAP database", "eventDate": "2026-11-25T00:00:00Z"},
    ],
    "status": ["client delete prohibited", "client transfer prohibited"],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET."}, {"ldhName": "B.IANA-SERVERS.NET."}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc"]],
            ],
        },
        {
            "roles": ["registrant", "technical"],
            "vcardArray": [
                "vcard",
                [
                    ["fn", {}, "text", "Jane Doe"],
                    ["email", {}, "text", "jane@private.example"],
                    ["tel", {}, "text", "+15551234567"],
                ],
            ],
        },
    ],
}


def values(findings, entity_type):
    return [f.value for f in findings if f.entity_type == entity_type]


def fake_resolver(answers=None, missing_dmarc=True):
    answers = DNS_ANSWERS if answers is None else answers

    async def resolve(name, rdtype):
        if name.startswith("_dmarc."):
            if missing_dmarc:
                raise dns.resolver.NXDOMAIN()
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.test"]
        if rdtype not in answers:
            raise dns.resolver.NoAnswer()
        return answers[rdtype]

    return resolve


async def test_dns_reports_records_and_a_missing_dmarc(monkeypatch):
    monkeypatch.setattr(domain_module, "resolve", fake_resolver())

    findings, errors = await _check_dns(DOMAIN)

    assert errors == []
    assert values(findings, "dns_a") == ["93.184.216.34", "93.184.216.34"]
    assert values(findings, "dns_aaaa") == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert values(findings, "dns_ns") == ["a.iana-servers.net", "b.iana-servers.net"]
    assert values(findings, "dns_mx") == ["mail.example.test", "backup.example.test"]

    primary_mx = next(f for f in findings if f.entity_type == "dns_mx")
    assert primary_mx.raw["preference"] == "10"

    spf = next(f for f in findings if f.entity_type == "spf")
    assert spf.raw["present"] is True
    assert spf.value.startswith("v=spf1")

    # A missing DMARC record is the finding, not the absence of one: it is a spoofing exposure.
    dmarc = next(f for f in findings if f.entity_type == "dmarc")
    assert dmarc.raw["present"] is False
    assert "no DMARC" in dmarc.value
    assert dmarc.confidence == 1.0


async def test_dns_finds_dmarc_when_published(monkeypatch):
    monkeypatch.setattr(domain_module, "resolve", fake_resolver(missing_dmarc=False))

    findings, _ = await _check_dns(DOMAIN)

    dmarc = next(f for f in findings if f.entity_type == "dmarc")
    assert dmarc.raw["present"] is True
    assert "p=reject" in dmarc.value


async def test_null_mx_is_reported_as_accepting_no_mail(monkeypatch):
    """RFC 7505: "0 ." is a deliberate statement, not a mail server called "0"."""
    monkeypatch.setattr(domain_module, "resolve", fake_resolver({"A": ["1.2.3.4"], "MX": ["0 ."]}))

    findings, errors = await _check_dns(DOMAIN)

    assert errors == []
    assert values(findings, "dns_mx") == []
    assert values(findings, "no_mx") == [f"{DOMAIN} publishes a null MX: it accepts no mail"]


async def test_dns_reports_a_missing_spf(monkeypatch):
    monkeypatch.setattr(domain_module, "resolve", fake_resolver({"A": ["1.2.3.4"]}))

    findings, errors = await _check_dns(DOMAIN)

    assert errors == []
    spf = next(f for f in findings if f.entity_type == "spf")
    assert spf.raw["present"] is False
    assert "no SPF" in spf.value


async def test_nxdomain_is_one_error_and_no_findings(monkeypatch):
    async def resolve(name, rdtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(domain_module, "resolve", resolve)

    findings, errors = await _check_dns(DOMAIN)

    assert findings == []
    assert errors == [f"{DOMAIN} does not exist (NXDOMAIN)"]


@respx.mock
async def test_crtsh_strips_wildcards_dedupes_and_filters_off_domain(client):
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "*.example.test\nwww.example.test"},
                {"name_value": "WWW.EXAMPLE.TEST"},
                {"name_value": "api.example.test"},
                {"name_value": "evil-example.test"},
                {"name_value": "example.test.attacker.com"},
                {"name_value": "other.com"},
                {"name_value": "example.test"},
                "not a dict",
            ],
        )
    )

    findings, errors = await _check_crtsh(DOMAIN, client)

    assert errors == []
    assert values(findings, "subdomain") == [
        "api.example.test",
        "example.test",
        "www.example.test",
    ]
    assert all(f.confidence == 0.9 for f in findings)
    assert all("crt.sh" in f.source_url for f in findings)


@respx.mock
async def test_crtsh_caps_the_subdomain_list(client, monkeypatch):
    monkeypatch.setattr(domain_module, "MAX_SUBDOMAINS", 3)
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(
            200, json=[{"name_value": f"host{n}.example.test"} for n in range(10)]
        )
    )

    findings, errors = await _check_crtsh(DOMAIN, client)

    assert len(findings) == 3
    assert len(errors) == 1
    assert "reporting the first 3" in errors[0]


@respx.mock
async def test_crtsh_failure_is_an_error_not_a_crash(client):
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ReadTimeout("too slow"))

    findings, errors = await _check_crtsh(DOMAIN, client)

    assert findings == []
    assert len(errors) == 1
    assert "crt.sh lookup failed" in errors[0]


@respx.mock
async def test_rdap_extracts_registration_data_and_drops_contacts(client):
    respx.get(f"https://rdap.org/domain/{DOMAIN}").mock(
        return_value=httpx.Response(200, json=RDAP_BODY)
    )

    findings, errors = await _check_rdap(DOMAIN, client)

    assert errors == []
    assert values(findings, "registrar") == ["Example Registrar Inc"]
    assert values(findings, "created") == ["1995-08-14T04:00:00Z"]
    assert values(findings, "expires") == ["2026-08-13T04:00:00Z"]
    assert values(findings, "last_changed") == ["2025-08-14T07:01:38Z"]
    assert values(findings, "rdap_nameserver") == ["a.iana-servers.net", "b.iana-servers.net"]
    assert values(findings, "domain_status") == [
        "client delete prohibited, client transfer prohibited"
    ]

    # Registrant personal data must not survive into a finding, redacted or not.
    blob = json.dumps([f.model_dump(mode="json") for f in findings])
    assert "Jane Doe" not in blob
    assert "private.example" not in blob
    assert "15551234567" not in blob


@respx.mock
async def test_rdap_404_is_a_clean_negative(client):
    respx.get(f"https://rdap.org/domain/{DOMAIN}").mock(return_value=httpx.Response(404))

    assert await _check_rdap(DOMAIN, client) == ([], [])


@respx.mock
async def test_internetdb_404_yields_nothing(client):
    respx.get("https://internetdb.shodan.io/1.2.3.4").mock(return_value=httpx.Response(404))

    assert await _check_internetdb(["1.2.3.4"], client) == ([], [])


@respx.mock
async def test_internetdb_reports_ports_cves_and_hostnames(client):
    respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip": "1.2.3.4",
                "ports": [22, 443],
                "hostnames": ["mail.example.test"],
                "cpes": ["cpe:/a:nginx:nginx:1.18.0"],
                "vulns": ["CVE-2021-23017"],
                "tags": [],
            },
        )
    )

    findings, errors = await _check_internetdb(["1.2.3.4"], client)

    assert errors == []
    assert values(findings, "open_port") == ["1.2.3.4:22", "1.2.3.4:443"]
    assert values(findings, "cve") == ["CVE-2021-23017"]
    assert values(findings, "reverse_hostname") == ["mail.example.test"]

    port = next(f for f in findings if f.entity_type == "open_port")
    assert port.raw["ip"] == "1.2.3.4"
    assert port.raw["cpes"] == ["cpe:/a:nginx:nginx:1.18.0"]

    cve = next(f for f in findings if f.entity_type == "cve")
    assert cve.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"


@respx.mock
async def test_wayback_summarises_and_keeps_only_interesting_urls(client):
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200,
            json=[
                ["timestamp", "original"],
                ["20150102030405", "http://example.test/index.html"],
                ["20160102030405", "http://example.test/files/payroll.xlsx"],
                ["20170102030405", "http://example.test/admin/panel"],
                ["20180102030405", "http://example.test/about"],
                ["20190102030405", "http://example.test/.env"],
                ["20200102030405", "http://example.test/report.pdf?v=2"],
            ],
        )
    )

    findings, errors = await _check_wayback(DOMAIN, client)

    assert errors == []
    summary = next(f for f in findings if f.entity_type == "archive_summary")
    assert summary.raw["captures"] == 6
    assert "2015-01-02 to 2020-01-02" in summary.value

    assert values(findings, "archived_url") == [
        "http://example.test/files/payroll.xlsx",
        "http://example.test/admin/panel",
        "http://example.test/.env",
        "http://example.test/report.pdf?v=2",
    ]
    assert all(f.confidence == 0.6 for f in findings if f.entity_type == "archived_url")


@respx.mock
async def test_wayback_empty_result_is_not_an_error(client):
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(200, json=[])
    )

    assert await _check_wayback(DOMAIN, client) == ([], [])


@respx.mock
async def test_wayback_caps_archived_urls(client, monkeypatch):
    monkeypatch.setattr(domain_module, "MAX_ARCHIVED_URLS", 2)
    rows = [["timestamp", "original"]]
    rows += [[f"2020010203040{n}", f"http://example.test/admin/{n}"] for n in range(5)]
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(200, json=rows)
    )

    findings, _ = await _check_wayback(DOMAIN, client)

    assert len(values(findings, "archived_url")) == 2


async def test_a_seed_that_is_not_a_hostname_is_rejected(client):
    from osint_agent.core.models import Seed, SeedType
    from osint_agent.modules.domain import run

    result = await run(Seed(type=SeedType.domain, value="not a domain"), client)

    assert result.findings == []
    assert len(result.errors) == 1
    assert "does not look like a domain" in result.errors[0]
