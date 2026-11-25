# lantern

A modular OSINT agent in Python that takes a single seed — an email address, username, phone
number, domain or person name — runs the matching collection modules concurrently, and prints
structured findings you can export as JSON. It is built for legitimate investigative work:
auditing your own exposure, authorized penetration tests, and threat-intelligence research.

The installed command is `osint`.

## Ethical use

Use this only against targets you are authorized to investigate.

- **Breach data is metadata only.** The HaveIBeenPwned module records a breach name, date and the
  categories of data exposed. It never requests, stores or displays passwords, hashes, or raw
  dump contents.
- **Public APIs only.** No authenticated scraping, no CAPTCHA circumvention, no undocumented
  endpoints. Search dorking goes through the Brave Search API, never by scraping result pages.
  The LinkedIn dork reads search results only; lantern never fetches LinkedIn itself.
- **No registrant personal data.** The RDAP lookup keeps registrar and lifecycle dates. Contact
  entities are dropped whether or not the registry redacted them.
- **Missing API keys degrade gracefully.** A module without its key is skipped with a warning
  rather than failing the run.
- **Rate limits are respected.** Requests are spaced per host, `retry-after` is honoured, and
  every request identifies itself as `lantern/0.2`.

A fuller `ACCEPTABLE_USE.md` lands in week 5.

## Install (Windows / PowerShell)

```powershell
cd "E:\Personal Project\OSINT-Agent"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
Copy-Item .env.example .env     # then fill in whichever keys you have
```

All keys are optional. See `.env.example` for what each one unlocks.

## Usage

```powershell
osint run --phone +60123456789          # fully offline, no API key needed
osint run --email someone@example.com
osint run --username torvalds
osint run --domain example.com
osint run --name "Jane Doe"

osint run --domain example.com --verbose        # raw payloads, full values, cache hits
osint run --domain example.com --no-cache       # ignore cached responses
osint run --email someone@example.com --json report.json
```

Exactly one seed flag is required per run. Seeds are normalized before use: domains lose their
scheme, path, port and `www.`; phone numbers become E.164; names have their whitespace collapsed.

## Modules

| Module | Seed | What it collects | API key |
|---|---|---|---|
| `phone` | phone | Validity, E.164/international format, region, carrier, line type, timezones | none (offline) |
| `email` | email | MX records, HIBP breach metadata, Gravatar profile + linked accounts, holehe service registrations | `HIBP_API_KEY` for breaches only |
| `username` | username | Claimed accounts across ~500 top sites via Maigret | none |
| `social` | username | GitHub, Reddit, Bluesky, Hacker News and Mastodon public profiles; linked URLs and accounts extracted from bios as pivots | `GITHUB_TOKEN` optional, raises the rate limit |
| `domain` | domain | DNS A/AAAA/MX/NS/TXT, SPF and DMARC presence, crt.sh subdomains, RDAP registration data, Shodan InternetDB ports and CVEs, Wayback archive summary and interesting archived URLs | none |
| `dork` | all five | Search-engine dork hits from the templates in `dorks/` | `BRAVE_API_KEY` |

A missing SPF or DMARC record is reported as a finding in its own right: it is a spoofing
exposure, not an absence of data.

### Dork templates

Queries live in `dorks/<seed type>.yaml`, so adding one needs no code change:

```yaml
- id: domain_data_files
  query: 'site:{value} (filetype:sql OR filetype:env OR filetype:log)'
  description: Exposed data, backup and configuration files
```

`{value}` is the normalized seed. Phone templates may also use `{national}` for the local format.
A run sends at most 8 dorks and keeps at most 10 results each, deduped by URL.

## Caching and rate limiting

Every module reaches the network through one shared layer, so repeated runs are fast and no
service gets hammered.

- **Cache**: `.cache/lantern.db` (SQLite, gitignored). Only `200` and `404` responses are stored —
  a 404 is a real answer, while `429` and `5xx` are not. Entries expire per module: 6h for
  search results and breach data, 12h for social profiles, 24h for DNS-adjacent lookups.
- **Cache keys** are a SHA-256 of the method, URL and public query params. Credentials travel in
  headers and are never hashed into a key or written to the cache file.
- **`--no-cache`** ignores stored responses but still caches fresh ones, so the next run benefits.
- **`--verbose`** logs every cache hit and outbound fetch to stderr.
- **Rate limiting**: one lock and one timestamp per host, with a per-host delay (crt.sh 2.0s,
  Reddit 2.0s, HIBP 1.6s, 0.5s default). A `429` is retried once, honouring `retry-after` up to
  30 seconds.

Delete `.cache/` any time to start clean.

## Development

```powershell
ruff check . ; ruff format .
pytest
pre-commit run --all-files
```

Tests never touch the network: HTTP is mocked with `respx` and DNS is faked at our own resolver
call.

## Roadmap

- ~~**Week 1** — core models, runner, email/username/phone modules, CLI.~~
- ~~**Week 2** — domain, dorking and social modules; shared HTTP cache and per-host rate limiting.~~
- **Week 3** — persistence: case files, SQLite storage, result diffing across runs, and pivoting
  on the `linked_url` / `linked_account` findings the social module already emits.
- **Week 4** — reporting: HTML/PDF export, entity graph visualisation.
- **Week 5** — `ACCEPTABLE_USE.md`, correlation engine that raises confidence when independent
  modules agree, plugin loader for third-party modules.

## License

MIT — see [LICENSE](LICENSE).
