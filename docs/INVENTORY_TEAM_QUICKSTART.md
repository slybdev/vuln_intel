# External Inventory Team Quick Start

This guide is for the team connecting an external application inventory to Vuln Intel. The flow is:

1. When an application with a GitHub or GitLab repository is added to the inventory, the inventory
   registers it with Vuln Intel.
2. Vuln Intel queues an initial scan and later posts the result to the inventory callback.
3. The inventory stores the returned CI trigger URL and application token for the repository.
4. The GitLab project calls that trigger URL from its pipeline on future runs.
5. Vuln Intel scans the exact pipeline commit and posts the result to the same callback.

The initial scan is asynchronous. Registration returns a queued scan ID; it does not wait for Trivy
to finish.

## Before integrating

Coordinate the following with the Vuln Intel administrator:

- The reachable Vuln Intel API origin, for example `http://192.0.2.10:8000`.
- The inventory management bearer token (`VULN_INVENTORY_API_TOKEN`).
- The callback URL the scan worker should call, for example
  `http://192.0.2.30:9000/integrations/vuln-intel/events`.
- The callback host/IP must be added to Vuln Intel's `VULN_INVENTORY_CALLBACK_HOSTS`.
- Self-hosted GitLab hosts must be added to `VULN_REPOSITORY_HOSTS`.
- Private-repository GitLab username and PAT credentials must be saved by the Vuln Intel
  administrator in Repository settings. Do not send the PAT in the inventory registration request.

Use addresses reachable from the inventory service, GitLab runner, and Vuln Intel worker. The
worker runs in a container, so `127.0.0.1` in a callback or repository URL refers to that container,
not the inventory or GitLab host. Prefer HTTPS. HTTP is only accepted for explicitly allowlisted
self-hosted GitLab and callback hosts and provides no transport encryption.

## 1. Register the application

Call the registration endpoint when an inventory application is created or its repository changes:

```http
POST http://192.0.2.10:8000/api/v1/inventory/repositories
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

Fields:

| Field | Required | Guidance |
|---|---:|---|
| `external_inventory_id` | Yes | Stable ID from your inventory, unique per application, maximum 200 characters. Reuse it for retries and updates. |
| `repository_url` | Yes | Repository root URL, including namespace/group and project. Its host must be allowlisted by Vuln Intel. |
| `callback_url` | Yes | Inventory endpoint that accepts signed JSON POST callbacks. Its hostname/IP must be allowlisted by Vuln Intel. |
| `name` | No | Human-readable application name. |

Do not include credentials, URL query strings, or fragments. The callback URL may include a path
and port, but not URL credentials, query strings, or fragments. Repository and callback host
allowlists contain hostnames/IPs only, without schemes or ports.

Example request using `curl`:

```bash
curl --fail --silent --show-error \
  --request POST "http://192.0.2.10:8000/api/v1/inventory/repositories" \
  --header "Authorization: Bearer $VULN_INVENTORY_API_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{
    "external_inventory_id": "cmdb:application:payments-api",
    "repository_url": "http://192.0.2.20:8080/platform/payments/backend.git",
    "callback_url": "http://192.0.2.30:9000/integrations/vuln-intel/events",
    "name": "Payments API"
  }'
```

### Registration response

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

Generated values are examples. Store `trigger_url`, `ci_token`, and `callback_secret` securely.
The inventory management token is for registration, credential rotation, and removal; it is not
the token for GitLab CI.

The first request normally returns `202 Accepted`. The initial scan starts from the repository's
default branch. Retrying registration with the same external ID and repository URL is safe: it
returns the existing credentials and does not enqueue a duplicate initial scan. If the repository
URL changes, send the same external ID with the new URL; Vuln Intel updates the connection and
queues a scan for the new target.

The `created` field indicates whether a new scan run was queued. It does not indicate whether the
repository record itself was newly created.

## 2. Store the returned values

For each application, store:

- `application_id` as Vuln Intel's ID for the registered repository.
- `trigger_url` in the GitLab project's CI/CD variables as `VULN_SCAN_TRIGGER_URL`.
- `ci_token` in the GitLab project's CI/CD variables as `VULN_SCAN_CI_TOKEN` (masked; protect it
  when appropriate).
- `callback_secret` in the inventory's secret store, keyed to this application.

The application CI token is scoped to the registered application. Do not share it between
repositories. The callback secret is used to verify callbacks and is different from both the
management token and CI token.

## 3. Add a GitLab CI scan job

The inventory team or repository owner adds a job to the GitLab project's pipeline. Vuln Intel
does not edit `.gitlab-ci.yml` or install a GitLab webhook automatically.

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

The request sent by the job is:

```json
{
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "ref": "main",
  "event_id": "42:381:vuln-intel-scan"
}
```

The SHA must be a full 40- or 64-character commit hash. The `event_id` must be unique for each
pipeline event and stable across retries of that event. A new request returns `202 Accepted` with a
scan ID; a retry of the same request returns `200 OK` with the existing scan. If the same event ID
is reused with a different SHA or ref, Vuln Intel returns `409 Conflict`.

The trigger endpoint queues work; it does not wait for the scan or return findings immediately.
Vuln Intel fetches and scans the exact commit from the request.

## 4. Receive and verify results

When the initial scan or a later CI scan completes, Vuln Intel sends a POST to the registered
`callback_url`. A successful event looks like:

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
    "ref": "main",
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

The callback includes these headers:

```http
Content-Type: application/json
X-Vuln-Event-ID: 8cf91e12-ae8c-4bbc-a590-1a2c859b5965
X-Vuln-Signature: sha256=<lowercase-HMAC-SHA256-hex>
```

Verify the signature over the exact raw request body bytes using the application's
`callback_secret`. Do not parse and re-serialize the JSON before checking the signature. Compare
the expected signature in constant time, then deduplicate by `event_id`. Delivery is at least once,
so a previously received event may be retried.

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
    if not event_already_processed(event["event_id"]):
        save_result(event)
        mark_event_processed(event["event_id"])
```

Return any `2xx` status to acknowledge delivery. Persist the event ID atomically with processing
where possible, so a retry cannot create duplicate inventory results. Vuln Intel does not follow
callback redirects.

Terminal scan failures use `event_type: "scan.failed"`, status `failed`, and a bounded error
summary. Transient worker failures are retried internally first. Callback delivery failures are
retried by Vuln Intel with backoff; the inventory should return a non-2xx only when it wants the
delivery retried.

The callback is a concise summary, not the full SBOM or raw Trivy reports. For complete scan
details, query the status endpoint with the application's CI token.

## 5. Optional: query scan status

Use the `run_id` from the registration response, trigger response, or callback:

```http
GET http://192.0.2.10:8000/api/v1/inventory/repositories/{application_id}/scans/{run_id}
Authorization: Bearer <application-ci-token>
```

Example:

```bash
curl --fail --silent --show-error \
  --header "Authorization: Bearer $VULN_SCAN_CI_TOKEN" \
  "http://192.0.2.10:8000/api/v1/inventory/repositories/$VULN_APPLICATION_ID/scans/$VULN_SCAN_RUN_ID"
```

The response contains the scan lifecycle status, counts, findings, and unevaluated matches. A token
for one application cannot read another application's scan.

## 6. What Vuln Intel does with a scan

For each queued run, the worker:

1. Gets the repository URL and encrypted Git provider credentials from PostgreSQL.
2. Resolves `HEAD` to the default branch's commit for the initial scan, or uses the exact SHA from
   the GitLab CI request.
3. Fetches a shallow checkout into a temporary directory.
4. Runs the configured Trivy version and creates a vulnerability report and CycloneDX SBOM.
5. Matches detected components to Vuln Intel's canonical advisory database and marks uncertain
   version-range matches as unevaluated instead of safe.
6. Persists scan history and findings. Only a successful complete scan updates current findings
   and resolves findings that were absent.
7. Queues a signed callback for the inventory.

The temporary repository checkout is removed after scanning. Scan records and findings are shown in
Vuln Intel's **Application scans** view. The inventory's callback provides a result summary for the
inventory's own UI and workflow.

## 7. Error responses and who to contact

| HTTP status | Meaning / next step |
|---|---|
| `202 Accepted` | Scan queued. Wait for callback or poll status. |
| `200 OK` | Idempotent retry; existing scan/credentials returned. |
| `400 Bad Request` | Check JSON fields, full commit SHA, ref, event ID, and repository/callback host allowlists. |
| `401 Unauthorized` | Check the bearer token and whether the correct token type is being used. |
| `404 Not Found` | Check application ID/run ID; the run may not belong to this application. |
| `409 Conflict` | Do not reuse an event ID for a different SHA or ref. |
| `413` / `415` | Request body exceeds 16 KiB or `Content-Type` is not `application/json`. |
| `503 Service Unavailable` | Vuln Intel's administrator needs to check API configuration or encryption-key setup. |

Contact the Vuln Intel administrator if the registration host or callback host is not allowlisted,
the worker cannot reach the repository/callback, or private repository credentials need to be
configured. Do not send the management token, CI token, callback secret, or GitLab PAT in tickets or
plain-text chat.

## Checklist

- [ ] Use a stable `external_inventory_id`.
- [ ] Send the repository root URL and inventory callback URL when registering.
- [ ] Store the returned `ci_token` and `callback_secret` securely.
- [ ] Add `trigger_url` and `ci_token` as GitLab CI/CD variables.
- [ ] Send the exact commit SHA, ref, and a stable pipeline `event_id`.
- [ ] Verify callback HMAC over raw bytes and deduplicate by `event_id`.
- [ ] Return `2xx` after processing and poll status only if additional details are needed.
