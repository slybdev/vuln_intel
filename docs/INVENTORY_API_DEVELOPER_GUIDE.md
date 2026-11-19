# Vuln Intel External Inventory API

This API registers applications and repositories and starts vulnerability scans.

## Base URL

Use the Vuln Intel server address supplied by the Vuln Intel team, for example:

```text
http://192.0.2.10:8000
```

Use the actual server IP or HTTPS address. Do not use `0.0.0.0` or `127.0.0.1` unless Vuln Intel
and the inventory are on the same machine.

## Authentication

Use two credentials:

| Credential | Used for |
|---|---|
| `VULN_INVENTORY_API_TOKEN` | Registering, changing, or removing applications |
| `CI_TOKEN` | Triggering or checking a scan for one application |

Send bearer authentication:

```http
Authorization: Bearer <TOKEN>
```

The application ID returned during registration is an identifier, not a password.

## 1. Register an application

```http
POST /api/v1/inventory/repositories
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
Content-Type: application/json
```

Request:

```json
{
  "external_inventory_id": "cmdb:application:payments-api",
  "repository_url": "http://192.0.2.20:8080/platform/payments/backend.git",
  "callback_url": "http://192.0.2.30:9000/integrations/vuln-intel/events",
  "name": "Payments API"
}
```

| Field | Required | Description |
|---|---:|---|
| `external_inventory_id` | Yes | Stable ID for this application in the inventory. |
| `repository_url` | Yes | GitHub or GitLab repository root URL. |
| `callback_url` | Yes | Your endpoint that receives scan results. |
| `name` | No | Display name. |



Response `202 Accepted`:

```json
{
  "repository": {
    "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
    "external_inventory_id": "cmdb:application:payments-api",
    "name": "Payments API",
    "repository_url": "http://192.0.2.20:8080/platform/payments/backend"
  },
  "trigger_url": "http://192.0.2.10:8000/api/v1/inventory/repositories/inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904/scans",
  "ci_token": "vint_ci_example_generated_token",
  "callback_secret": "vint_cb_example_generated_secret",
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

Store:

- `repository.application_id`
- `trigger_url`
- `ci_token`
- `callback_secret`

The initial scan starts asynchronously. This response means the scan was queued, not that it has
finished.

Retrying registration with the same `external_inventory_id` is safe. It returns the existing
credentials. Change the URL and use the same ID when a repository changes.

## 2. Trigger a rescan

Add this request to the GitLab pipeline:

```http
POST <trigger_url>
Authorization: Bearer <ci_token>
Content-Type: application/json
```

Request body:

```json
{
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "ref": "refs/heads/main",
  "event_id": "42:381:vuln-intel-scan"
}
```

| Field | Required | Description |
|---|---:|---|
| `commit_sha` | Yes | Full 40- or 64-character commit SHA. |
| `ref` | Yes | Branch or tag ref, for example `refs/heads/main`. |
| `event_id` | Yes | Unique pipeline event ID. Reuse it only when retrying the same event. |

Response `202 Accepted`:

```json
{
  "scan": {
    "run_id": "5b44b034-b897-4eaf-85aa-2cba8a822101",
    "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "ref": "refs/heads/main",
    "status": "queued",
    "requested_at": "2026-11-18T12:15:00+00:00"
  },
  "created": true
}
```

`200 OK` means the same event was retried. `409 Conflict` means the event ID was reused with a
different commit or ref.

Example GitLab job:

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
      curl --fail --show-error \
        --header "Authorization: Bearer $VULN_SCAN_CI_TOKEN" \
        --header "Content-Type: application/json" \
        --data "$payload" \
        "$VULN_SCAN_TRIGGER_URL"
```



## 3. Receive scan results

Vuln Intel sends a `POST` to the `callback_url` after the scan succeeds or fails.

Callback headers:

```http
Content-Type: application/json
X-Vuln-Event-ID: 8cf91e12-ae8c-4bbc-a590-1a2c859b5965
X-Vuln-Signature: sha256=<HMAC-SHA256-HEX>
```

Successful callback body:

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
    "finding_count": 2,
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

`component_count` is the number of scanned components.

`finding_count` is the number of component-vulnerability finding rows. It is not necessarily the
number of unique vulnerable packages.

`unevaluated_count` is the number of matches that could not be evaluated safely.

A terminal failure callback uses:

```json
{
  "event_id": "8cf91e12-ae8c-4bbc-a590-1a2c859b5965",
  "event_type": "scan.failed",
  "external_inventory_id": "cmdb:application:payments-api",
  "application_id": "inventory:dc45e534d2015bde8cc4bb2f2fc386f54290c7668fe28904",
  "scan": {
    "run_id": "5b44b034-b897-4eaf-85aa-2cba8a822101",
    "status": "failed",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "ref": "refs/heads/main",
    "error": "Repository checkout failed."
  }
}
```

## 4. Verify callbacks

Verify `X-Vuln-Signature` over the exact raw HTTP body using `callback_secret`.

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

event = json.loads(raw_body)
# Store event["event_id"] to make processing idempotent.
process_event(event)
```

Return an HTTP `2xx` response after processing. Vuln Intel retries callbacks that fail or return a
non-2xx response. Callback events may be delivered more than once, so deduplicate using
`event_id`.

## 5. Check a scan

```http
GET /api/v1/inventory/repositories/{application_id}/scans/{run_id}
Authorization: Bearer <ci_token>
```

The response includes the status, counts, findings, and unevaluated matches.

## 6. Rotate or remove an application

Rotate the CI token:

```http
POST /api/v1/inventory/repositories/{application_id}/credential
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
```

```json
{
  "external_inventory_id": "cmdb:application:payments-api",
  "ci_token": "vint_ci_new_generated_token"
}
```

Remove the application:

```http
DELETE /api/v1/inventory/repositories/{application_id}
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
```

```json
{
  "removed": true,
  "external_inventory_id": "cmdb:application:payments-api"
}
```

## HTTP errors

| Status | Meaning |
|---|---|
| `400` | Invalid JSON or request fields. |
| `401` | Missing or invalid bearer token. |
| `404` | Application or scan was not found. |
| `409` | Event ID was reused with a different commit or ref. |
| `413` | Request body is too large. |
| `415` | `Content-Type` is not `application/json`. |
| `503` | Vuln Intel API configuration or required key is unavailable. |
