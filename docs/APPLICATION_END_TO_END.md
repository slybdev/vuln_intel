# Vuln Intel: End-to-End Application Guide

This guide follows data through the application from the public vulnerability feeds to PostgreSQL,
the dashboard, repository scans, and an external inventory callback. It includes a realistic
GitLab-on-a-private-network example. Addresses, IDs, and secrets below are examples; replace them
with values reachable in your network and keep real secrets out of source control.

For the exact endpoint contract and operational examples, see
[EXTERNAL_INVENTORY_API.md](./EXTERNAL_INVENTORY_API.md).

## 1. System overview

Vuln Intel has two related flows:

1. **Vulnerability intelligence ingestion** updates the central advisory database from NVD, OSV,
   GitHub Security Advisories (GHSA), CISA KEV, and EPSS.
2. **Application scanning** inventories dependencies in a Git repository, scans them with Trivy,
   matches those components to the central advisory database, and stores application-specific scan
   history and findings.

An external inventory can register a repository once. Vuln Intel queues its initial default-branch
scan and returns a URL plus an application-scoped token for future GitLab CI scans. When a scan
finishes or reaches a terminal failure, Vuln Intel posts a signed event to the inventory's callback.

```text
Public feeds ──> collect ──> raw files ──> normalize / deduplicate ──> PostgreSQL
                                                                        │
GitLab CI / inventory ──> dashboard API ──> scan_runs queue ──> worker ├─> Trivy
                                                                        │   └─> correlate with advisories
External inventory <── signed callback outbox <── persisted scan result ┘
```

The feed pipeline is not automatically scheduled by the dashboard or scan worker. Run
`python main.py` on a schedule (for example, with cron or Task Scheduler) to keep advisory data
fresh. The scan worker is a separate long-running process that consumes repository scans and
callback deliveries.

### Main code paths

| Responsibility | Entry point / implementation |
|---|---|
| Feed CLI and collect/process orchestration | `main.py`, `vuln_intel/cli.py`, `vuln_intel/pipeline.py` |
| Per-source API and file collectors | `vuln_intel/collectors/` |
| Source mapping, validation, alias resolution, and standardization | `vuln_intel/normalization/` |
| PostgreSQL schema and advisory persistence | `vuln_intel/database.py` |
| Dashboard HTTP API and static UI | `vuln_intel/dashboard.py`, `vuln_intel/web/` |
| Repository validation and encrypted provider credentials | `vuln_intel/repository_connections.py` |
| Scan request validation, queue persistence, and history | `vuln_intel/scan_service.py`, `vuln_intel/scan_store.py` |
| Git checkout, Trivy execution, and worker loop | `vuln_intel/scan_worker.py` |
| SBOM/report parsing and vulnerability correlation | `vuln_intel/scan_matching.py` |
| External registration, scoped credentials, and callbacks | `vuln_intel/inventory_integration.py` |

## 2. Feed ingestion: where the global vulnerability data comes from

### 2.1 Start a collection and processing run

Running:

```bash
python main.py
```

uses the default `--phase all` mode. In order, the CLI runs `run_collect` and then `run_process`.
Useful alternatives:

```bash
python main.py --phase collect
python main.py --phase process
python main.py --sources nvd,kev
python main.py --since 2026-11-01T00:00:00Z
```

`--phase process` reprocesses saved raw runs without downloading the feeds again. This is useful
after a normalization fix.

### 2.2 Incremental collectors

Each source has its own collection state and watermark:

| Source | Collection behavior |
|---|---|
| NVD | Paged NVD API 2.0 queries over a last-modified time window. Large backfills are split into bounded windows. |
| OSV | Reads each configured ecosystem's `modified_id.csv`, then downloads the changed advisory JSON records. |
| GHSA | Queries the GitHub advisories endpoint using a modified-time filter and follows pagination links. |
| CISA KEV | Downloads the catalog and compares entries against the prior snapshot. |
| EPSS | Downloads the daily compressed CSV and retains scores for CVEs Vuln Intel already tracks or discovered in this run. |

The window starts at the source's last successful watermark minus `OVERLAP_HOURS` (six hours by
default). On a source's first run, it starts at `FIRST_RUN_LOOKBACK_HOURS` (24 hours by default).
Overlapping data catches late source updates; later deduplication makes re-fetching safe. A source
watermark advances only after that source completes successfully. A failed or partial source is
retried in a later run instead of silently advancing past missing data.

### 2.3 Preserve raw data before interpreting it

Each source that returns a collection result (including a partial result) is written as an envelope
under:

```text
VULN_DATA_DIR/raw/<run_id>/<source>.json
```

The envelope records the source, run ID, collection window, completion state, notes, record count,
and raw records. Run state and source watermarks are held in `VULN_DATA_DIR/state/`; reports and
logs are also written under `VULN_DATA_DIR/`.

This raw-first boundary is intentional: if a mapper or schema rule needs a correction, the saved
run can be processed again without relying on the source to reproduce the same response.

### 2.4 Normalize, validate, and deduplicate

Processing reads each raw record and:

1. Calls the source-specific mapper to convert it into the common advisory view.
2. Validates required fields and data types. Invalid records go to
   `VULN_DATA_DIR/rejected/<run_id>.json`; one rejected record does not stop the rest of the run.
3. Expands bundled records that refer to multiple CVEs so separate vulnerabilities do not get
   merged accidentally.
4. Resolves identifiers and aliases (for example, a CVE linked to a GHSA and OSV ID) into one
   vulnerability entity.
5. Normalizes dates, severity/CVSS, ecosystems, package identities, affected ranges, CWEs, and
   reference URLs.
6. Replaces that source's prior contribution with its newest contribution, then merges contributions
   into the current canonical record.

Conceptually, a stored advisory looks like this (illustrative, abbreviated):

```json
{
  "id": "CVE-2025-12345",
  "ids": ["CVE-2025-12345", "GHSA-abcd-efgh-1234", "OSV-2025-123"],
  "sources": ["ghsa", "nvd", "osv"],
  "title": "Example package vulnerability",
  "severity": "HIGH",
  "affected": [
    {
      "ecosystem": "npm",
      "package": "example-package",
      "scheme": "semver",
      "ranges": [{"expr": ">=1.0.0, <1.4.2"}],
      "patched": ["1.4.2"],
      "sources": ["ghsa", "osv"]
    }
  ],
  "exploitation": {
    "in_kev": false,
    "epss": {"score": 0.18, "percentile": 0.71, "date": "2026-11-18"}
  }
}
```

The database stores canonical vulnerability payloads in `vulnerabilities`, aliases in
`vulnerability_ids`, source-specific normalized contributions in `source_contributions`, and
processed-run markers in `processed_runs`. PostgreSQL writes for a processed run are transactional.
If `VULN_DATABASE_URL` is unset, the legacy JSON store is used instead.

The dashboard reads these global records. The repository scanner uses them as one of its
correlation sources; it does not replace the feed-ingestion pipeline.

## 3. Configure Git credentials and hosts

Before scanning private repositories, an administrator saves a Git provider username and token in
**Repository settings**:

- GitLab: use a personal access token with `read_repository`.
- GitHub: use a token with repository Contents read access.

Credentials are encrypted in PostgreSQL using `VULN_REPOSITORY_ENCRYPTION_KEY`. They are selected by
repository provider and reused for that provider; GitLab credentials are currently shared across
all configured GitLab hosts, not separately scoped to each host. GitHub credentials are verified
against GitHub when saved. GitLab repository access is checked when the worker fetches the
repository.

The settings API only accepts loopback clients. Configure credentials on the server or through an
SSH tunnel rather than exposing unauthenticated settings to the network.

Repository hosts are controlled by `VULN_REPOSITORY_HOSTS`, a comma-separated hostname/IP
allowlist. Standard GitHub and `gitlab.com` repositories require HTTPS. HTTP is accepted only for
an explicitly allowlisted self-hosted GitLab host. HTTP exposes the Git credential during Git
transport; use it only on a trusted isolated network.

## 4. Register a repository from an external inventory

### 4.1 Request

Assume:

- Vuln Intel is reachable at `http://192.0.2.10:8000`.
- Self-hosted GitLab is at `http://192.0.2.20:8080`.
- The external inventory callback is at `http://192.0.2.30:9000`.

The addresses are documentation examples. Configure the actual API URL, repository host, and
callback host so they are reachable from the inventory, GitLab runner, and scan-worker container
respectively.

The inventory authenticates registration with `VULN_INVENTORY_API_TOKEN`:

```http
POST /api/v1/inventory/repositories
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
Content-Type: application/json
```

```json
{
  "external_inventory_id": "cmdb:application:payments-api",
  "repository_url": "http://192.0.2.20:8080/platform/payments/backend.git",
  "callback_url": "http://192.0.2.30:9000/integrations/vuln-intel/events",
  "name": "Payments API"
}
```

`external_inventory_id` is the stable identity assigned by the inventory. `name` is optional.
Repository and callback hosts must be configured in their respective allowlists:

```dotenv
VULN_INVENTORY_API_TOKEN=<long-random-management-token>
VULN_PUBLIC_API_BASE_URL=http://192.0.2.10:8000
VULN_REPOSITORY_HOSTS=github.com,gitlab.com,192.0.2.20
VULN_INVENTORY_CALLBACK_HOSTS=192.0.2.30
VULN_REPOSITORY_ENCRYPTION_KEY=<stable-fernet-key>
```

The host allowlists contain hosts only, without schemes or ports. URL ports are allowed. The
callback host must be reachable from the worker container. Do not set the public base URL to
`0.0.0.0`; that is a bind address, not a destination callers can use. The public base URL must be
an HTTP(S) origin with no path.

### 4.2 What the registration endpoint does

The dashboard validates the JSON, checks both allowlists, and derives a Vuln Intel application ID
from the external inventory ID. It stores a repository connection and an inventory integration in
PostgreSQL, then enqueues an initial scan with `HEAD` as the target. `HEAD` tells the worker to
resolve and scan the repository's current default-branch commit.

It also generates:

- `application_id`: Vuln Intel's stable ID for this registered application.
- `trigger_url`: the URL to save in GitLab CI for future exact-commit scans.
- `ci_token`: a token scoped to this application for the trigger and scan-status endpoints.
- `callback_secret`: the HMAC signing secret the inventory must use to verify result callbacks.

Example response (generated values are illustrative; tokens must be stored as secrets):

```http
HTTP/1.1 202 Accepted
Content-Type: application/json
```

```json
{
  "repository": {
    "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
    "external_inventory_id": "cmdb:application:payments-api",
    "name": "Payments API",
    "repository_url": "http://192.0.2.20:8080/platform/payments/backend"
  },
  "trigger_url": "http://192.0.2.10:8000/api/v1/inventory/repositories/inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904/scans",
  "ci_token": "vint_ci_<generated-secret>",
  "callback_secret": "vint_cb_<generated-secret>",
  "scan": {
    "run_id": "5b44b034-b897-4eaf-85aa-2cba8a822101",
    "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
    "commit_sha": "HEAD",
    "ref": "HEAD",
    "status": "queued",
    "requested_at": "2026-11-18T12:15:00+00:00"
  },
  "created": true
}
```

The actual HTTP response is asynchronous: it confirms the scan was queued, not that Trivy has
finished. The inventory gets the result later through the callback, or can query the status
endpoint.

Registration is idempotent. Retrying the same external ID and repository URL returns the existing
credentials and does not enqueue a duplicate initial scan (`200 OK` when that scan already
exists). Reusing an external ID with a changed repository URL updates its connection and queues a
scan for the updated repository. If returned
credentials are lost, retry registration with the same external ID to retrieve the stored values.
If only the CI token needs to be invalidated, use the credential-rotation endpoint; it rotates the
CI token, not the callback signing secret.

The `created` response field indicates whether a new initial scan run was queued. It is not a
separate indicator that the repository or integration record was newly inserted.

The registration request is made by the inventory service, not by GitLab CI. The management token
must remain in the inventory's secret store. It is not the GitLab PAT and is not the token CI uses
for scans.

## 5. Initial scan: queue to Trivy result

The `scan-worker` continuously claims queued work from PostgreSQL. For the initial `HEAD` request it:

1. Loads the application repository URL and the saved provider credentials.
2. Resolves the repository's default branch and current commit with Git.
3. Updates the scan record to that exact commit SHA and ref.
4. Fetches that commit shallowly into a temporary working directory. Credentials are supplied to
   Git through a temporary askpass helper; they are not embedded into the repository URL.
5. Runs the pinned Trivy version against the repository and writes a Trivy JSON report and a
   CycloneDX SBOM.
6. Parses components and findings from both outputs, then removes the temporary checkout.
7. Combines Trivy's findings with package advisories from Vuln Intel's PostgreSQL database.
8. Persists scan metadata, components, findings, and evaluation results. Report/SBOM files are
   retained in the worker's configured scan-artifact volume.

Repository contents are not kept as a persistent clone, and the worker does not execute repository
code. Trivy checks repository dependencies; it is not a scan of a built container image, running
host, or deployed environment.

### 5.1 How internal matching works

For each package, the scanner matches the component's ecosystem/name and installed version against
affected package ranges in the central advisory database. Trivy and internal-feed matches are
merged by component and canonical vulnerability identity, while the result keeps source labels and
evidence. The current version comparators evaluate PEP 440 and SemVer ranges. If a version scheme,
package identity, or required distribution release cannot be safely evaluated, the match is stored
as **unevaluated** rather than treated as safe.

### 5.2 Scan persistence and the UI

The main scan tables are:

| Table | What it stores |
|---|---|
| `repository_connections` | Application ID, display name, and repository URL. |
| `scan_runs` | Commit/ref, queue and lifecycle status, timestamps, retry data, counts, scanner details, and report hashes. |
| `scan_components` | Normalized dependency components for a scan. |
| `scan_findings` | Findings for that specific scan, including identity, severity, sources, and evidence. |
| `scan_match_evaluations` | Advisory matches that could not safely be classified by the supported version comparators. |
| `application_findings` | Current findings for each application/ref, including first/last seen and active/resolved state. |

Only a successful complete scan updates current application/ref findings and resolves findings
that were absent from the new successful scan. A failed scan does not make old findings disappear.
The **Application scans** view lists registered repositories, external inventory IDs, scan history,
components, and findings.

## 6. Future rescans from GitLab CI

After registration, add these GitLab CI/CD variables:

| Variable | Value | GitLab setting |
|---|---|---|
| `VULN_SCAN_TRIGGER_URL` | Exact `trigger_url` from registration | Regular variable |
| `VULN_SCAN_CI_TOKEN` | Exact `ci_token` from registration | Masked; protect it if the job runs only on protected refs |

The API does not install a GitLab webhook or edit the repository's pipeline. The GitLab project
owner adds a job that calls the supplied URL. Example:

```yaml
vuln-intel-scan:
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      payload="$(jq -n \
        --arg commit_sha "$CI_COMMIT_SHA" \
        --arg ref "$CI_COMMIT_REF_NAME" \
        --arg event_id "$CI_PROJECT_ID:$CI_PIPELINE_ID:$CI_JOB_NAME" \
        '{commit_sha:$commit_sha, ref:$ref, event_id:$event_id}')"
      curl --fail --silent --show-error \
        --request POST "$VULN_SCAN_TRIGGER_URL" \
        --header "Authorization: Bearer $VULN_SCAN_CI_TOKEN" \
        --header "Content-Type: application/json" \
        --data "$payload"
```

The job sends the exact commit and ref:

```http
POST /api/v1/inventory/repositories/{application_id}/scans
Authorization: Bearer <application-ci-token>
Content-Type: application/json
```

```json
{
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "ref": "refs/heads/main",
  "event_id": "42:381:vuln-intel-scan"
}
```

`commit_sha` must be a full 40- or 64-character hexadecimal SHA. `event_id` must be unique for
each pipeline event and reused unchanged when retrying that event. A new accepted request returns
`202 Accepted`; a repeat with the same event, SHA, and ref returns `200 OK` with the existing scan.
Reusing an event ID for a different SHA or ref returns `409 Conflict`. The API returns immediately
after queueing; it does not wait for Trivy.

The per-application CI token cannot register or remove repositories. It is separate from the
inventory management token, the GitLab PAT, and the legacy standalone scan token
`VULN_SCAN_API_TOKEN`.

## 7. Result callback: worker back to the inventory

When a scan succeeds or reaches a terminal failure, the worker inserts a callback event in
`inventory_callback_outbox` in the same PostgreSQL transaction that changes the scan state. The
worker later claims the event, signs the exact serialized body, and sends an HTTP POST to the
registered callback URL.

Successful callback example:

```http
POST /integrations/vuln-intel/events
Content-Type: application/json
X-Vuln-Event-ID: 8cf91e12-ae8c-4bbc-a590-1a2c859b5965
X-Vuln-Signature: sha256=<HMAC-SHA256-hex>
```

```json
{
  "event_id": "8cf91e12-ae8c-4bbc-a590-1a2c859b5965",
  "event_type": "scan.completed",
  "external_inventory_id": "cmdb:application:payments-api",
  "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
  "scan": {
    "run_id": "5b44b034-b897-4eaf-85aa-2cba8a822101",
    "status": "succeeded",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "ref": "refs/heads/main",
    "requested_at": "2026-11-18T12:15:00+00:00",
    "started_at": "2026-11-18T12:15:02+00:00",
    "completed_at": "2026-11-18T12:17:43+00:00",
    "component_count": 120,
    "finding_count": 1,
    "unevaluated_count": 1,
    "findings": [
      {
        "vulnerability_id": "CVE-2025-12345",
        "canonical_id": "CVE-2025-12345",
        "ecosystem": "npm",
        "package_name": "example-package",
        "installed_version": "1.2.3",
        "fixed_version": "1.4.2",
        "severity": "HIGH",
        "sources": ["trivy", "vuln_intel"]
      }
    ]
  }
}
```

The callback contains a compact findings summary, not the full SBOM or raw Trivy reports. A
terminal failure uses `event_type: "scan.failed"`, status `failed`, and a bounded error summary.
Transient scan errors are retried internally; they do not produce a terminal failure callback until
the retry limit is reached.

### 7.1 Verify the signature and deduplicate

The signature is HMAC-SHA256 over the **exact raw UTF-8 request body**, using the
`callback_secret` returned during registration. Verify before parsing/re-serializing JSON, compare
in constant time, and deduplicate by `event_id`. Delivery is at least once, so duplicate events are
possible.

Generic Python verification logic:

```python
import hashlib
import hmac
import json

raw_body = request_body_bytes
received = request_headers["X-Vuln-Signature"]
expected = "sha256=" + hmac.new(
    callback_secret.encode("utf-8"),
    raw_body,
    hashlib.sha256,
).hexdigest()

if not hmac.compare_digest(received, expected):
    reject_request()
else:
    event = json.loads(raw_body)
    if event["event_id"] not in processed_event_ids:
        process_event(event)
        persist_processed_event_id(event["event_id"])
```

Return any `2xx` response to acknowledge delivery. Redirects are not followed. Failed deliveries
stay in the durable outbox and are retried with exponential backoff capped at one hour.

## 8. Polling a scan result

The CI token can also query a scan by ID:

```http
GET /api/v1/inventory/repositories/{application_id}/scans/{run_id}
Authorization: Bearer <application-ci-token>
```

While queued/running, the response exposes lifecycle status and counts. Once complete, it includes
the findings and unevaluated matches. The token can only read scans for its own application; a run
belonging to a different application returns `404 Not Found`.

Example completed result (abbreviated):

```json
{
  "run_id": "5b44b034-b897-4eaf-85aa-2cba8a822101",
  "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "ref": "refs/heads/main",
  "status": "succeeded",
  "requested_at": "2026-11-18T12:15:00+00:00",
  "started_at": "2026-11-18T12:15:02+00:00",
  "completed_at": "2026-11-18T12:17:43+00:00",
  "component_count": 120,
  "finding_count": 1,
  "unevaluated_count": 1,
  "scanner_version": "0.76.2",
  "findings": [
    {
      "canonical_id": "CVE-2025-12345",
      "vulnerability_id": "CVE-2025-12345",
      "ecosystem": "npm",
      "package_name": "example-package",
      "installed_version": "1.2.3",
      "fixed_version": "1.4.2",
      "severity": "HIGH",
      "sources": ["trivy", "vuln_intel"],
      "evidence": {}
    }
  ],
  "unevaluated": [
    {
      "canonical_id": "GHSA-example",
      "ecosystem": "npm",
      "package_name": "another-package",
      "reason": "The package has matching advisory data, but its version scheme or range could not be evaluated safely.",
      "evidence": {}
    }
  ]
}
```

## 9. Credential roles and security boundaries

| Credential/configuration | Used by | Purpose |
|---|---|---|
| GitLab username + PAT | Scan worker | Fetch private GitLab repositories; encrypted at rest; never returned to the inventory. |
| `VULN_INVENTORY_API_TOKEN` | External inventory | Register repositories, rotate CI credentials, and remove registrations. Keep it in the inventory's secret store. |
| `ci_token` returned at registration | One GitLab application/pipeline | Trigger that application's scans and query its scan results. Store as a masked CI variable. |
| `callback_secret` returned at registration | External inventory callback receiver | Verify Vuln Intel's signed callback payloads. |
| `VULN_SCAN_API_TOKEN` | Other CI clients using `POST /api/scans` | Legacy/general scan API authorization; it is not the inventory app token. |
| `VULN_REPOSITORY_ENCRYPTION_KEY` | Dashboard and scan worker | Encrypt/decrypt saved provider and integration secrets. It must remain stable and identical across both processes. |

The dashboard API base URL must be reachable from the inventory and GitLab runner. Repository
URLs must be reachable from the worker. Callback URLs must be reachable from the worker container.
For containers, `127.0.0.1` refers to that container, not the Docker host. Use network-routable
addresses and protect non-loopback HTTP traffic with a trusted isolated network or an authenticated
TLS reverse proxy.

## 10. Operational checklist and common failures

Before testing a registration:

- PostgreSQL is running and both dashboard and worker point to the same database.
- `VULN_REPOSITORY_ENCRYPTION_KEY` is configured identically for dashboard and worker.
- The dashboard has `VULN_INVENTORY_API_TOKEN` and a reachable
  `VULN_PUBLIC_API_BASE_URL`.
- Self-hosted GitLab and callback hosts are in the appropriate exact-host allowlists.
- The GitLab provider username/PAT is saved in Repository settings.
- The worker can reach GitLab, Trivy's vulnerability database, PostgreSQL, and the callback host.
- The GitLab runner can reach the returned `trigger_url`.

Common API statuses:

| Status | Typical cause |
|---|---|
| `400` | Malformed JSON, invalid SHA/ref/event ID, unsupported repository URL, or host not allowlisted. |
| `401` | Missing/incorrect management or application bearer token. |
| `404` | Unknown application/scan, or scan ID does not belong to the authenticated application. |
| `409` | Same idempotency event ID reused with a different SHA or ref. |
| `413` / `415` | Request exceeds the 16 KiB limit or is not `application/json`. |
| `503` | Required integration configuration or encryption key is missing/invalid. |
| `202` | Scan accepted and queued; wait for callback or poll its run ID. |

For exact routes, rotation/removal examples, and the full response contract, continue to
[EXTERNAL_INVENTORY_API.md](./EXTERNAL_INVENTORY_API.md).
