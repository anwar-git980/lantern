# osint-agent

A modular OSINT agent in Python that takes a single seed — an email address, a username, or a
phone number — runs the matching collection modules concurrently, and prints structured findings
you can export as JSON. It is built for legitimate investigative work: auditing your own exposure,
authorized penetration tests, and threat-intelligence research.

## Ethical use

Use this only against targets you are authorized to investigate.

- **Breach data is metadata only.** The HaveIBeenPwned module records a breach name, date and the
  categories of data exposed. It never requests, stores or displays passwords, hashes, or raw
  dump contents.
- **Public APIs only.** No authenticated scraping, no CAPTCHA circumvention, no undocumented
  endpoints.
- **Missing API keys degrade gracefully.** A module without its key is skipped with a warning
  rather than failing the run.

A fuller `ACCEPTABLE_USE.md` lands in week 5.

## Install (Windows / PowerShell)

```powershell
cd "E:\Personal Project\OSINT-Agent"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
Copy-Item .env.example .env     # then add your HIBP key if you have one
```

## Usage

```powershell
osint run --phone +60123456789          # fully offline, no API key needed
osint run --email someone@example.com
osint run --username torvalds
osint run --email someone@example.com --json report.json --verbose
```

Exactly one seed flag is required per run.

## Modules

| Module | Seed | What it collects | API key |
|---|---|---|---|
| `phone` | phone | Validity, E.164/international format, region, carrier, line type, timezones | none (offline) |
| `email` | email | MX records, HIBP breach metadata, Gravatar profile + linked accounts, holehe service registrations | `HIBP_API_KEY` for breaches only |
| `username` | username | Claimed accounts across ~500 top sites via Maigret | none |

## Roadmap

- **Week 2** — domain and name modules; correlation engine that raises confidence when independent modules agree.
- **Week 3** — persistence: case files, SQLite storage, result diffing across runs.
- **Week 4** — reporting: HTML/PDF export, entity graph visualisation.
- **Week 5** — `ACCEPTABLE_USE.md`, rate-limit budgeting, plugin loader for third-party modules.

## License

MIT — see [LICENSE](LICENSE).
