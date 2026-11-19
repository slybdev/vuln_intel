# Getting started

This guide takes you from a fresh copy of the project to a daily automated run.

## 1. What you need

| Requirement | Notes |
|---|---|
| Python 3.9 or newer | Check with `python --version`. |
| Docker Compose | Runs the local PostgreSQL 16 database. |
| PostgreSQL driver | Installed with the project requirements. |
| Outbound HTTPS access | To the five hosts listed under *Network access* below. |
| NVD API key (recommended) | Free. Request one at <https://nvd.nist.gov/developers/request-an-api-key>. Without it NVD allows far fewer requests, so the pipeline pauses longer between pages. |
| GitHub token (optional) | Raises the GitHub API rate limit. Reading public advisories should not need special scopes. |

### Network access

If you run this inside a bank network, allow outbound HTTPS to:

| Source | Host |
|---|---|
| NVD | `services.nvd.nist.gov` |
| OSV | `osv-vulnerabilities.storage.googleapis.com` |
| GitHub advisories | `api.github.com` |
| CISA KEV | `www.cisa.gov` |
| EPSS | `epss.empiricalsecurity.com` |

The HTTP client honors the standard `HTTPS_PROXY` / `HTTP_PROXY` environment variables, so a corporate proxy works without code changes.

## 2. Install and start PostgreSQL

```bash
unzip vuln-intel.zip
cd vuln-intel
python --version         # must be 3.9+
python -m pip install -e .
docker compose up -d postgres
```

Compose stores database files in the named `vuln-intel-postgres` volume and only exposes PostgreSQL
on localhost. The example credentials are for local development; change them before exposing the
database to any other host.

## 3. Configure

Linux / macOS:
```bash
export NVD_API_KEY="your-nvd-key"
export GITHUB_TOKEN="your-github-token"
export VULN_DATABASE_URL="postgresql://vulnintel:vulnintel@127.0.0.1:5432/vulnintel"
```

Windows PowerShell:
```powershell
$env:NVD_API_KEY = "your-nvd-key"
$env:GITHUB_TOKEN = "your-github-token"
$env:VULN_DATABASE_URL = "postgresql://vulnintel:vulnintel@127.0.0.1:5432/vulnintel"
```

After collecting data, start the API from the project directory (or an activated project
environment):

```powershell
python -m vuln_intel.dashboard --host 127.0.0.1 --port 8081
```

In another terminal, start the Tactical Ops UI:

```powershell
npx --yes bun install
npx --yes bun run dev
```

Then open <http://127.0.0.1:3000>. The UI proxies API requests to port `8081`; keep both services
bound to localhost for local use. The production container serves the built UI and API on port `8000`.

| Variable | Default | Meaning |
|---|---|---|
| `VULN_DATABASE_URL` | unset | PostgreSQL connection string. If unset, legacy JSON storage is used. |
| `POSTGRES_DB` | `vulnintel` | Database name used by Compose. |
| `POSTGRES_USER` | `vulnintel` | Local database user used by Compose. |
| `POSTGRES_PASSWORD` | `vulnintel` | Local development password; change it for shared deployments. |
| `POSTGRES_PORT` | `5432` | Host port for the local container. |
| `NVD_API_KEY` | none | Higher NVD rate limit |
| `GITHUB_TOKEN` | none | Higher GitHub rate limit |
| `VULN_DATA_DIR` | `./vuln_data` | Where all output is written |
| `OSV_ECOSYSTEMS` | `PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist` | Which OSV ecosystems to follow. Trim this to what you actually run. |
| `GHSA_TYPES` | `reviewed` | Any of `reviewed`, `unreviewed`, `malware` (comma separated) |
| `FIRST_RUN_LOOKBACK_HOURS` | `24` | How far back the very first run looks |
| `OVERLAP_HOURS` | `6` | Each run re-pulls this much before the last success, to catch late edits |

Keep keys out of the repository and out of shell history where you can; in production load them from your secret store into the job's environment.

## 3b. Check the install (no network needed)

```bash
python3 -m unittest discover -s tests -t .
```
All tests should pass. They use fake sources, so this confirms the code works on your machine before you touch the real internet.

## 4. First run

```bash
python3 main.py
```

`main.py` does everything in one go:

1. **Pull** the latest changes from all five sources and save them untouched under `vuln_data/raw/<run_id>/`.
2. **Clean** the data: validate each record, map it to one schema, merge duplicates across sources, standardize ecosystems and version ranges.
3. **Store** canonical records, searchable identifiers, per-source contributions, and processed-run
   markers in PostgreSQL; then print a summary report.

You will see a banner showing your settings, one log line per source, then the report. It looks like this (numbers are illustrative):

```
NVD API key    : set
...
[nvd] collecting window 2026-11-10T08:32:58Z -> 2026-11-11T08:32:58Z
[nvd] 312 records
[osv] 140 records
...
VULNERABILITY INTELLIGENCE REPORT  run 20261111T083258Z
Entities in database      : 421
New entities this run     : 421
Rejected by validation    : 0
Touched entities that are in CISA KEV (3):
  CVE-...
RESULT: success
```

The first run only looks back 24 hours for NVD, OSV and GitHub by default, while CISA KEV loads its
full catalog. **This is an incremental-start setting, not a complete historical backfill**: use
`--since` for a larger window or raise `FIRST_RUN_LOOKBACK_HOURS` before first collection if you
need older records. Deep OSV backfills can be slow; for full historical coverage, verify each
source's collection strategy and completion status rather than assuming a successful daily run
contains every historical advisory.

### Useful flags

```bash
python3 main.py --sources nvd,kev              # only some sources
python3 main.py --phase collect                # only pull raw data
python3 main.py --phase process                # only process raw data not yet processed
python3 main.py --since 2026-11-01T00:00:00Z   # start the window earlier (backfill)
```

Exit code is `0` on success and `1` if any source failed, which your scheduler can alert on.

## 5. Where to find results

| Location | What it is |
|---|---|
| PostgreSQL `vulnerabilities` | **The database.** One JSONB record per canonical vulnerability ID. |
| PostgreSQL `vulnerability_ids` | Unique identifier/alias index pointing to its canonical vulnerability. |
| PostgreSQL `source_contributions` | Latest normalized contribution for each source record, enabling correct replacement and re-merging. |
| PostgreSQL `processed_runs` | Prevents a raw run from being processed repeatedly after successful commit. |
| `reports/report_<run_id>.txt` | Plain-text summary of each run |
| `raw/<run_id>/<source>.json` | Exactly what each source returned |
| `rejected/<run_id>.json` | Records that failed validation, with reasons |
| `state/` | Collection watermarks and KEV snapshot. Back this up with the PostgreSQL volume. |
| `logs/pipeline.log`, `logs/runs.jsonl` | Detailed log and one JSON line per run |

### Reading the database

Python:
```python
import os
import psycopg

with psycopg.connect(os.environ["VULN_DATABASE_URL"]) as conn:
    db = {
        row[0]["id"]: row[0]
        for row in conn.execute("SELECT payload FROM vulnerabilities").fetchall()
    }

# Actively exploited, highest exploit probability first
hot = sorted((e for e in db.values() if e["exploitation"]["in_kev"]),
             key=lambda e: (e["exploitation"]["epss"] or {}).get("score", 0), reverse=True)
for e in hot[:10]:
    print(e["id"], e["severity"], e["exploitation"]["epss"])

# Everything affecting a Maven package
for e in db.values():
    for a in e["affected"]:
        if a["ecosystem"] == "Maven":
            print(e["id"], a["package"], [r["expr"] for r in a["ranges"]])
```

SQL:
```sql
SELECT payload->>'id' AS id, payload->>'severity' AS severity
FROM vulnerabilities
WHERE payload->'exploitation'->>'in_kev' = 'true';
```

## 6. Run it daily

Pick a time after the day's EPSS file is published. EPSS is generated daily, reportedly shortly after 13:30 UTC, so **15:00 UTC** is a safe choice. The report's `[epss] score_date=` note shows which day's scores you got. Running earlier still works; you just get the previous day's EPSS scores.

**cron**
```cron
0 15 * * * cd /opt/vuln-intel && set -a && . ./.env && set +a && python3 main.py >> cron.log 2>&1
```
where `.env` contains lines like `NVD_API_KEY=...` (cron does not load your shell environment).

**systemd** (`/etc/systemd/system/vuln-intel.service` and `.timer`):
```ini
# vuln-intel.service
[Unit]
Description=Vulnerability intelligence pipeline
[Service]
Type=oneshot
WorkingDirectory=/opt/vuln-intel
EnvironmentFile=/etc/vuln-intel.env
ExecStart=/usr/bin/python3 main.py

# vuln-intel.timer
[Unit]
Description=Run vuln-intel daily
[Timer]
OnCalendar=*-*-* 15:00:00 UTC
Persistent=true
[Install]
WantedBy=timers.target
```
Then `systemctl enable --now vuln-intel.timer`. A non-zero exit marks the unit failed, so you can alert on it.

**Windows**: create a Task Scheduler task that runs `python main.py` with the project folder as the start directory.

## 7. Day-to-day operation

- **Safe to re-run.** Running twice in a day does not create duplicates.
- **A source failed?** The other sources still complete. The failed source's window is retried automatically on the next run because its watermark was not advanced.
- **Processing crashed?** Run `python3 main.py --phase process`. Raw runs are only marked processed after the database is written.
- **Backfill.** Use `--since`. NVD is split into windows automatically (slow without an API key). For OSV, `--since` fetches each changed record one by one, which is fine for days or weeks but not for years; a one-time bulk load from OSV's `all.zip` files would suit a deep backfill (not implemented yet).
- **Start from scratch.** Delete the `vuln_data` folder.
- **Disk growth.** `raw/` gains a folder per run. Once a run is processed you can archive or delete old folders (you only need them to reprocess).
- On the first PostgreSQL run, if the legacy JSON database and its contribution file exist, they are
imported automatically along with processed-run markers. The import refuses to proceed if the
vulnerability database exists but source contributions are missing, because that would make later
source updates destructive.

**Back up** the PostgreSQL volume and `state/` together. Raw run snapshots are also useful for
reprocessing or auditing.

## 8. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `NVD ... HTTP 403` or `429` in the log | Throttled. Set `NVD_API_KEY`. The client already retries with backoff. |
| Run is slow | No NVD key (pauses ~6.5 s between NVD pages). Add the key, or narrow `OSV_ECOSYSTEMS`. |
| `Network error` for every source | Egress blocked or proxy needed. Check the host list above and set `HTTPS_PROXY`. |
| `[osv] partial result; watermark NOT advanced` | One OSV ecosystem or record failed. Re-run; check `logs/pipeline.log` for which one. |
| `Rejected by validation: N` in the report | Look in `rejected/<run_id>.json`. A few rejects are normal; many suggest a source changed its format. |
| EPSS matched 0 rows | Normal on the very first run if no CVEs were collected. Otherwise check that `[epss] score_date` is recent. |
| `HTTP 404` on the EPSS or KEV URL | The provider moved the file. Update the URL in `vuln_intel/config.py`. |
| Report shows the same entities as "updated" every day | Expected for EPSS: scores change daily, so entities in the database get refreshed. |

## 9. Security notes

- Everything fetched is public data; the only secrets are the two optional API tokens.
- Records from external sources are treated as untrusted data: they are parsed as JSON/CSV and never executed.
- Run the job with a dedicated low-privilege account that can write only to the data directory.
