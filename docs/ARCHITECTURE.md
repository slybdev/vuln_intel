# Architecture: what was built and why

## Purpose

Phase 2 and Phase 3 of the vulnerability management pipeline: gather vulnerability intelligence from external sources every day, then turn it into one clean, standardized database that later phases (asset matching, prioritization) can rely on.

## How it maps to the diagram

| Diagram box | Where it lives in the code |
|---|---|
| External sources (NVD, OSV, GitHub, CISA KEV, EPSS) | `vuln_intel/collectors/` (one module each) |
| Scheduled data ingestion & polling | `main.py` run by cron / systemd (see `GETTING_STARTED.md`), plus per-source watermarks in `state/state.json` |
| API feed integration & extraction pipeline | `vuln_intel/pipeline.py` → `run_collect` |
| Tactical Ops UI and vulnerability API | `src/`, `vuln_intel/dashboard.py`, `dashboard_data.py` |
| Raw vulnerability intelligence ingested | `vuln_data/raw/<run_id>/<source>.json` |
| Field mapping & schema validation | `normalization/mappers/` and `normalization/schema.py` |
| Duplicate detection & entity resolution | `normalization/resolver.py` |
| Ecosystem standardization & version ranges | `normalization/ecosystems.py`, `versions.py`, `cvss.py` |
| Standardized vulnerability database | PostgreSQL `vulnerabilities` table (payloads built by `merge.py`) |
| Identifier/alias index | PostgreSQL `vulnerability_ids` table (unique identifier to canonical ID) |
| Source-specific normalized contributions | PostgreSQL `source_contributions` table |
| Application scan queue and history | PostgreSQL `scan_runs`, `scan_components`, and `scan_findings` |
| Current app/ref findings | PostgreSQL `application_findings`, updated only after a successful complete scan |
| External inventory registrations and scoped CI credentials | PostgreSQL `inventory_integrations` |
| Durable signed scan callbacks | PostgreSQL `inventory_callback_outbox`, delivered by `scan_worker.py` |
| Repository scanning and report storage | `vuln_intel/scan_worker.py` and the Compose `scan-worker` service |
| Trivy/internal advisory correlation | `vuln_intel/scan_matching.py` and `scan_service.py` |

## Data flow

```
 main.py
   │
   ├─ COLLECT  (pipeline.run_collect)
   │    NVD ─┐
   │    OSV ─┤   each collector: ask "what changed since my watermark?"
   │    GHSA ┼─► raw/<run_id>/<source>.json        (saved untouched)
   │    KEV ─┤   watermark advances only if the source fully succeeded
   │    EPSS ┘   (EPSS runs last, for the CVEs the others found)
   │
   └─ PROCESS  (pipeline.run_process, for each unprocessed raw run)
        raw record
          → mapper            source-specific fields → one "view" shape
          → validate          bad records go to rejected/, the run continues
          → expand            a record bundling several CVEs is split per CVE
          → entity store      records sharing any ID/alias join the same entity
          → merge             one standardized record per entity
          → PostgreSQL transaction + reports/report_<run_id>.txt
```

## How each source is collected

| Source | Method | Why |
|---|---|---|
| NVD | REST API 2.0, filtered by last-modified window, paged | Only fetches what changed. Windows are capped at 120 days, so long backfills are chunked. |
| OSV | Public bucket: per-ecosystem `modified_id.csv` lists changed IDs, then fetch those JSON files | Efficient incremental pull; avoids per-package queries. |
| GitHub advisories | REST `/advisories` with the `modified` filter, following `Link` headers | Date-granular filter; overlap is deduplicated later. |
| CISA KEV | Download the whole JSON, compare each entry's hash to the last snapshot | KEV has no changelog, but the file is small. |
| EPSS | Download the daily gzipped CSV, keep only CVEs we track | The file covers every CVE; storing all of them daily would be wasteful. |

## The standardized record

Each vulnerability in the database looks like this (abridged):

| Field | Meaning |
|---|---|
| `id` | Canonical ID. A CVE if one exists, otherwise a GHSA ID, otherwise the source ID. |
| `ids` | Every identifier and alias known for it (CVE, GHSA, OSV IDs) |
| `sources`, `source_ids` | Which sources contributed, and under which IDs |
| `title`, `description` | Best available text (NVD description preferred) |
| `published`, `modified`, `withdrawn` | UTC timestamps, one format everywhere |
| `severity`, `cvss_best`, `cvss[]` | Normalized severity label, the preferred CVSS entry, and all CVSS entries seen |
| `cwes` | Weakness IDs merged across sources |
| `affected[]` | Per package: `ecosystem`, `package`, `scheme`, `ranges[]` (each with an `expr` such as `>=2.0-beta9, <2.15.0`), `patched`, `sources`. NVD entries use ecosystem `cpe` with `vendor`. |
| `references` | Deduplicated URLs |
| `exploitation` | `in_kev`, KEV details (due date, ransomware use), and EPSS `score` / `percentile` / `date` |
| `first_seen`, `last_seen`, `last_changed`, `content_hash` | Change tracking for later phases |

## Application repository scans

CI submits an authenticated `POST /api/scans` request containing `application_id`, full `commit_sha`,
`ref`, and provider `event_id`. The API returns a scan ID and queues work in PostgreSQL. An
administrator saves GitHub/GitLab credentials once, then registers each application by its HTTPS
repository URL. Provider credentials are encrypted at rest using `VULN_REPOSITORY_ENCRYPTION_KEY`;
repository settings APIs accept loopback clients only. Keep the dashboard bound to localhost or place
an authenticated reverse proxy in front of it before remote access. The worker chooses credentials
based on the repository host, fetches only the requested commit into an ephemeral working directory,
and removes it after scanning. It does not keep a persistent clone or execute repository code.
Provider tokens must be scoped to the repositories the operator intends to scan. An operator can
queue a manual scan from the repository settings view; the worker resolves the provider's default
branch to an exact commit before fetching it. CI can submit a specific commit through `POST /api/scans`,
which remains protected by `VULN_SCAN_API_TOKEN`.

An external inventory can register repositories through
`POST /api/v1/inventory/repositories`, authenticated by `VULN_INVENTORY_API_TOKEN`. Registration
creates a connection associated with the external inventory ID, queues an idempotent initial
default-branch scan, and returns a per-application CI token and callback signing secret. GitLab CI
uses the scoped token to request exact-commit scans. Completion and terminal-failure events are
inserted into `inventory_callback_outbox` in the same transaction as the scan state change, then
delivered by the worker with HMAC-SHA256 signatures and retry backoff. The dashboard joins these
registrations to repository connections so they appear in the existing application scan view.
See `docs/EXTERNAL_INVENTORY_API.md` for the request/response contract and deployment settings.

The worker stores Trivy JSON and CycloneDX reports in its persistent Docker volume. Scan runs,
components, and findings are separate from the canonical global vulnerability-feed records. Trivy
findings and internal-feed matches are combined by component and canonical vulnerability ID, while
their detection sources and evidence remain distinct. The internal matcher uses package URL or
ecosystem/name identity plus the installed version and affected ranges; the current version evaluators
support PEP 440 and SemVer. Unsupported or incomplete version data is recorded as unevaluated and
shown for review, never treated as proof that a package is safe. Only a successful complete scan
updates current application/ref findings and resolves findings absent from that scan.

## Key design decisions

1. **Raw first.** Every response is saved untouched before anything is parsed. A parsing bug becomes a reprocessing job (`--phase process`), not a lost day.
2. **Watermark per source, advanced only on success.** A failure never creates a silent gap.
3. **Overlapping windows plus idempotent upserts.** Each run re-pulls a few hours before the watermark; duplicates are absorbed by the store (unchanged and older-than-stored records are skipped).
4. **Each source's data is kept separately and re-merged.** When a source updates a record, its old data is replaced rather than accumulated, so removed version ranges actually disappear.
5. **Entity resolution by alias graph.** If a record links two entities (for example an OSV record listing both a CVE and a GHSA ID), they are merged.
6. **Bundled advisories are split.** Distro advisories listing several CVEs would otherwise wrongly merge distinct vulnerabilities.
7. **One version-range format.** NVD (`versionEndExcluding`), OSV (events) and GitHub (`">= 1, < 2"`) all become the same interval shape, so identical ranges from different sources collapse into one.
8. **Failure isolation.** One source down or one bad record never stops the rest.
9. **PostgreSQL storage.** Canonical records, source contributions, identifier uniqueness, and processed-run markers are persisted transactionally. Raw responses remain in the filesystem for audit and reprocessing.
10. **Single HTTP choke point** (`http_client.http_get`): retries, backoff and proxy support in one place, and tests can fake every source without network access.

## Testing

`tests/` has unit tests for normalization, Trivy report/SBOM parsing, package matching, scan API
authentication, and feed collection. Feed end-to-end tests use fake sources and require no network.
PostgreSQL scan persistence can be exercised against the Compose database.

The dashboard binds to localhost by default. Put an authenticated reverse proxy in front of it before
exposing scan results or the scan-request endpoint outside the local machine.

## Known limitations

- Internal version matching currently supports only PEP 440 and SemVer; other schemes remain unevaluated.
- Repository scans do not replace scans of built images, root filesystems, or deployed hosts.
- GitHub and gitlab.com repositories require HTTPS. Allowlisted self-hosted GitLab hosts may use HTTP; GitLab credentials are shared per provider.
- NVD configurations are flattened: only `vulnerable: true` matches are used and AND/OR logic is ignored.
- CVSS v4 scores are not calculated (the vector is kept). v3.x scores are calculated when only a vector is available.
- Entries removed from CISA KEV are not detected.
- OSV `GIT` commit ranges are skipped.
- Deep historical backfill of OSV is slow (see `GETTING_STARTED.md`).

## Natural next steps

- Extend ecosystem-specific version comparison to Maven, NuGet, RubyGems, Composer, Debian, and Alpine.
- Add `trivy image` scans for deployed applications using immutable image digests.
- Add provider-native GitHub App/GitLab OAuth connections and CI provider's signed-event verification.
- Add query-specific indexes or a search index as usage grows.
- Alerting on new KEV entries and on large EPSS jumps.
