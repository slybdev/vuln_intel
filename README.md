# Tactical Ops — Vulnerability Intelligence

Daily vulnerability intelligence pipeline: pulls the latest changes from **NVD, OSV, GitHub Security
Advisories, CISA KEV and EPSS**, preserves raw source records, normalizes and deduplicates them, and
stores the standardized records and source contributions in PostgreSQL. The Tactical Ops React UI
provides the overview, repository scanning, vulnerability intelligence, asset inventory, security
logs, and scheduled feed pages.

Python 3.9+, PostgreSQL 16+, Docker Compose.

## Run it

Start PostgreSQL:

```bash
docker compose up -d postgres
```

Install the Python dependencies and configure the database URL:

```bash
python -m pip install -e .
```

For persistent local settings, copy `.env.example` to `.env` in the project root. The Python
application loads `.env` at startup, while variables already set in the process environment take
precedence. Keep the `.env` file private and retain the same repository encryption key across restarts.

PowerShell:

```powershell
$env:VULN_DATABASE_URL = "postgresql://vulnintel:vulnintel@127.0.0.1:5432/vulnintel"
python3 main.py
```
The command **pulls** raw data, **cleans** it (validate, map to one schema, resolve duplicates,
standardize ecosystems and version ranges), and stores the result in PostgreSQL. Raw source
responses, reports, logs, and collection watermarks remain under `vuln_data/`.

Without `VULN_DATABASE_URL`, the program retains its legacy JSON storage mode for local tests and
backward compatibility.

Start the vulnerability API in a second terminal:

```powershell
$env:VULN_DATABASE_URL = "postgresql://vulnintel:vulnintel@127.0.0.1:5432/vulnintel"
python -m vuln_intel.dashboard --host 127.0.0.1 --port 8081
```

Start the Tactical Ops UI from the project root:

```powershell
npx --yes bun install
npx --yes bun run dev
```

Open <http://127.0.0.1:3000>. The Vite development server proxies API requests to the local Python
service on port `8081`. The **Overview**, **Applications**, **Application Scans**, **Intelligence**,
**Asset Inventory**, **Security Logs**, and **Feed Schedule** pages use the PostgreSQL-backed API.

Build the combined production image from the project root:

```bash
docker build -t vuln-intel .
```

The image serves the built Tactical Ops UI and API on port `8000`. Supply `VULN_DATABASE_URL` and
any required integration secrets at runtime; they are not copied into the image. From inside a
container, `127.0.0.1` refers to that container, so configure a database hostname reachable on its
Docker network.

## Application repository scans

In **Repository settings**, save GitHub and/or GitLab credentials once, then add each application
using its repository URL and application ID. The worker selects the saved credentials from the
URL's provider. Credentials are encrypted in PostgreSQL with Fernet and shared across repositories
for that provider. Public repositories can be added without provider credentials. GitHub does not
accept account passwords for HTTPS Git access: enter the GitHub username and a fine-grained personal
access token with read-only Contents permission.
Saving GitHub credentials first verifies the token with GitHub and checks that its authenticated account
matches the entered username; rejected or unreachable tokens are not stored. This confirms token
authentication, while access to a specific repository's contents is confirmed when that repository is scanned.
That token can only access the repositories granted to it; configure its repository access to include
every repository you intend to scan. For GitLab, use a personal access token with `read_repository`
scope and the corresponding username. Add self-hosted GitLab hostnames/IPs to
`VULN_REPOSITORY_HOSTS`. Self-hosted GitLab may use an HTTP URL when its host is allowlisted; GitHub
and gitlab.com require HTTPS. HTTP transmits credentials without encryption, so use it only on a
trusted isolated network. The scan worker fetches only the requested commit into a
temporary working directory, runs the pinned Trivy version, and discards the working copy afterward.
This is a shallow temporary checkout, not a persistent repository clone. Repository URLs must use an
allowed host. After adding a repository, click **Scan now** to scan the latest default-branch commit.
Alternatively, open **Application scans**, paste a GitHub HTTPS or configured GitLab repository URL,
and submit it to register the repository and queue a scan of its latest default-branch commit.
Private repositories use the saved credentials for that provider; public repositories can be scanned
without them.
CI can also queue scans for an exact commit as described below.
An external inventory can register repositories, receive signed callback results, and obtain an
application-scoped GitLab CI trigger URL and token; see
[docs/EXTERNAL_INVENTORY_API.md](docs/EXTERNAL_INVENTORY_API.md) for the full setup and API contract.

Configure the worker and start it with PostgreSQL:

```powershell
$env:VULN_DATABASE_URL = "postgresql://vulnintel:vulnintel@127.0.0.1:5432/vulnintel"
$env:VULN_SCAN_API_TOKEN = "random-long-ci-token"
$env:VULN_REPOSITORY_ENCRYPTION_KEY = "paste-your-saved-fernet-key-here"
docker compose up -d --build postgres scan-worker
vuln-intel-dashboard --host 0.0.0.0 --port 8000
```

Generate the Fernet key once with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` and
store it in a secret manager. Keep it stable and set the same value wherever the dashboard and worker
run; changing or losing it makes saved repository credentials unreadable. Repository settings are
available to local clients only. Do not expose the dashboard directly to the internet; put an
authenticated TLS reverse proxy in front of it if traffic leaves a trusted local network. Do not
commit any tokens or encryption keys.
`--host 0.0.0.0` makes the dashboard listen on all network interfaces; `--port` selects its listening
port. The dashboard serves plain HTTP. For a local setup, a runner on the same machine can use
`http://127.0.0.1:8000/api/scans`; a runner on another machine should use the dashboard machine's
reachable private IP and port, such as `http://192.168.1.50:8000/api/scans`. The bind address
`0.0.0.0` is not a client URL. HTTP sends the bearer token without transport encryption, so use it
only on a trusted isolated network; use an authenticated TLS reverse proxy otherwise.

`VULN_SCAN_TRIGGER_URL` is not generated by the dashboard. Set it as a GitLab CI/CD variable to the
address reachable from the runner. For a runner on another local machine, replace the example IP
with the dashboard machine's private IP and include the port it listens on. Do not use `0.0.0.0` in
that variable; it is only a bind address. `127.0.0.1` works only when the runner shares the
dashboard's network namespace.
`VULN_REPOSITORY_HOSTS` defaults to `github.com,gitlab.com`. CI calls the authenticated scan endpoint
using the application ID, full commit SHA, ref, and a provider event ID:

```powershell
$env:VULN_SCAN_TRIGGER_URL = "http://192.168.1.50:8000/api/scans"
$body = @{
  application_id = "app-12"
  commit_sha = "0123456789abcdef0123456789abcdef01234567"
  ref = "refs/heads/main"
  event_id = "provider-event-id"
} | ConvertTo-Json
Invoke-RestMethod -Uri $env:VULN_SCAN_TRIGGER_URL -Method Post `
  -Headers @{ Authorization = "Bearer $env:VULN_SCAN_API_TOKEN" } `
  -ContentType "application/json" -Body $body
```

In GitLab, configure `VULN_SCAN_TRIGGER_URL` as a regular CI/CD variable and
`VULN_SCAN_API_TOKEN` as a masked (and, where appropriate, protected) CI/CD variable. Set the URL
to the IP and port reachable from the runner, or to the TLS proxy address if one is used.
The endpoint returns `202 Accepted` and a scan ID; retries with the same application/event ID are
idempotent. The dashboard’s **Application scans** view shows run status and findings. Raw Trivy JSON
and CycloneDX reports are stored in the `vuln-intel-scan-data` Docker volume.

Internal version matching currently evaluates **PEP 440** and **SemVer** ranges. Other schemes,
missing package identity, or missing distro release data are shown as unevaluated rather than
reported as safe. Trivy results and internal-feed matches retain separate source evidence. A failed
or incomplete scan never resolves findings from the previous successful scan. The dashboard server
is localhost-only by default; use an authenticated reverse proxy before exposing it beyond localhost.

Optional API credentials: `NVD_API_KEY`, `GITHUB_TOKEN` (both only raise rate limits).

```bash
python3 main.py --sources nvd,kev              # only some sources
python3 main.py --phase process                # only process raw data not yet processed
python3 main.py --since 2026-11-01T00:00:00Z   # backfill window start
```

## Documentation

- [BACKEND_SETUP.md](BACKEND_SETUP.md): local Tactical Ops UI and API startup
- [docs/INVENTORY_API_DEVELOPER_GUIDE.md](docs/INVENTORY_API_DEVELOPER_GUIDE.md): simple API handoff for the external inventory team
- [docs/EXTERNAL_INVENTORY_API.md](docs/EXTERNAL_INVENTORY_API.md): repository registration, GitLab CI triggers, signed result callbacks, and credential operations
- [docs/INVENTORY_TEAM_QUICKSTART.md](docs/INVENTORY_TEAM_QUICKSTART.md): practical integration steps for the external inventory team
- [docs/APPLICATION_END_TO_END.md](docs/APPLICATION_END_TO_END.md): end-to-end feed ingestion, repository scanning, inventory registration, and callback flow
- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md): setup, first run, reading the output, daily scheduling, troubleshooting
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): what was built, how it maps to the diagram, design decisions, limitations

## Layout

```
main.py                         one-command entry point
vuln_intel/
  config.py  utils.py  http_client.py
  collectors/                   nvd, osv, ghsa, kev, epss
  normalization/                mappers/, schema, ecosystems, versions, cvss, resolver, merge
  reporting.py  pipeline.py  cli.py  dashboard.py  dashboard_data.py
src/                            Tactical Ops React UI
tests/                          unit + end-to-end tests (no network needed)
docs/
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```
