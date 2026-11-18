# External Inventory API

This API lets an external inventory register a GitHub or GitLab repository, receive its initial
scan result at a callback URL, and obtain an application-scoped credential and trigger URL for
future GitLab CI scans. Registered repositories and their scan history appear in the Vuln Intel
**Application scans** view.

## End-to-end flow

1. An administrator configures the Git provider credentials in **Repository settings**. For a
   private GitLab repository, save the GitLab username and a personal access token with
   `read_repository` scope. The token is encrypted in PostgreSQL and reused for all configured
   GitLab repositories.
2. The external inventory calls the registration endpoint with its application ID, repository URL,
   and callback URL. It authenticates using the inventory API token.
3. Vuln Intel validates the repository and callback hosts against configured allowlists, creates a
   repository connection, and queues an initial scan of the repository's default branch. The
   response includes the generated Vuln Intel application ID, scan ID, CI trigger URL, an
   application-scoped CI token, and a callback-signing secret.
4. The worker fetches the requested commit using the saved GitLab/GitHub credentials, runs Trivy,
   correlates findings with Vuln Intel's vulnerability database, and stores the scan in PostgreSQL.
   The application and findings are visible in **Application scans**.
5. After a successful scan, or a terminal scan failure, the worker sends a signed callback to the
   inventory. Callback events are persisted in an outbox and retried with exponential backoff.
6. On later pipeline runs, GitLab CI calls the returned trigger URL with the exact commit SHA, ref,
   and a unique event ID. The worker scans that commit and sends the result to the same callback.

## Configuration

Set these variables for the dashboard process:

| Variable | Required | Meaning |
|---|---:|---|
| `VULN_INVENTORY_API_TOKEN` | Yes | High-entropy bearer token used by the inventory for registration, credential rotation, and removal. |
| `VULN_PUBLIC_API_BASE_URL` | Yes | Public origin reachable by the inventory and GitLab runner, such as `http://192.168.1.50:8000` (scheme, host, optional port; no path). Do not use `0.0.0.0` or `127.0.0.1` for remote callers. |
| `VULN_REPOSITORY_ENCRYPTION_KEY` | Yes | Stable Fernet key used to encrypt Git provider and inventory credentials at rest. |
| `VULN_REPOSITORY_HOSTS` | Yes for self-hosted GitLab | Exact comma-separated repository hostnames or IPs. For example: `github.com,gitlab.com,192.168.1.20`. Do not include schemes or ports; custom ports in repository URLs are allowed. |
| `VULN_INVENTORY_CALLBACK_HOSTS` | Yes | Exact comma-separated callback hostnames or IPs reachable from the scan-worker container. Do not include schemes or ports; the callback URL may specify a port. |
| `VULN_DATABASE_URL` | Yes | PostgreSQL connection string used by the dashboard and worker. |

The worker also needs `VULN_REPOSITORY_ENCRYPTION_KEY`, `VULN_REPOSITORY_HOSTS`, and
`VULN_INVENTORY_CALLBACK_HOSTS`. Compose passes these settings to the worker.
The inventory integration uses `VULN_INVENTORY_API_TOKEN` for registration and an app-scoped token
for pipeline requests; it does not use `VULN_SCAN_API_TOKEN`, which remains for the standalone
`POST /api/scans` endpoint.

For example, for a local dashboard reachable at `192.168.1.50:8000`, a self-hosted GitLab at
`192.168.1.20`, and an inventory callback listener at `192.168.1.60`:

```dotenv
VULN_INVENTORY_API_TOKEN=<long-random-secret>
VULN_PUBLIC_API_BASE_URL=http://192.168.1.50:8000
VULN_REPOSITORY_HOSTS=github.com,gitlab.com,192.168.1.20
VULN_INVENTORY_CALLBACK_HOSTS=192.168.1.60
VULN_REPOSITORY_ENCRYPTION_KEY=<stable-fernet-key>
```

Start the worker and bind the dashboard to the network interface:

```powershell
docker compose up -d --build postgres scan-worker
vuln-intel-dashboard --host 0.0.0.0 --port 8000
```

`0.0.0.0` is only the server bind address. It is not a URL that a client can call. The dashboard
serves plain HTTP. Use it only on a trusted isolated network; use an authenticated TLS reverse proxy
when traffic crosses an untrusted network. Never commit tokens, GitLab PATs, or encryption keys.

### GitLab credentials and HTTP repository URLs

In the UI, open **Repository settings**, select **GitLab**, enter the GitLab username and a personal
access token with `read_repository`, then save. This provider credential is shared across GitLab
repositories. It is never returned by the settings API. Repository access is ultimately verified
when the worker fetches the repository. Repository settings accept loopback clients only; open the
dashboard on the server or use an SSH tunnel to configure credentials remotely.

GitHub and `gitlab.com` repository URLs must use HTTPS. HTTP is accepted for self-hosted GitLab only
when that host is explicitly listed in `VULN_REPOSITORY_HOSTS`. HTTP sends the PAT without transport
encryption; only use it on a trusted isolated network. The repository host must be reachable from
the worker container. In particular, `127.0.0.1` inside the worker refers to the worker itself, not
the host machine.

## 1. Register a repository

**Request**

```http
POST /api/v1/inventory/repositories
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
Content-Type: application/json
```

```json
{
  "external_inventory_id": "asset-42",
  "repository_url": "http://192.168.1.20/platform/payments.git",
  "callback_url": "http://192.168.1.60:9000/vuln-intel/results",
  "name": "Payments API"
}
```

`name` is optional. `external_inventory_id` must be stable and unique in the external inventory.
Repository URLs must point to a repository root and use an allowlisted host. Callback URLs must use
an allowlisted host; URL credentials, query strings, and fragments are rejected. Callback redirects
are not followed.

**New registration response — `202 Accepted`**

```json
{
  "repository": {
    "application_id": "inventory:...",
    "external_inventory_id": "asset-42",
    "name": "Payments API",
    "repository_url": "http://192.168.1.20/platform/payments"
  },
  "trigger_url": "http://192.168.1.50:8000/api/v1/inventory/repositories/inventory:.../scans",
  "ci_token": "vint_ci_...",
  "callback_secret": "vint_cb_...",
  "scan": {
    "run_id": "...",
    "status": "queued"
  },
  "created": true
}
```

The `ci_token` and `callback_secret` are sensitive. Store them securely. Registration is
idempotent: retrying the same `external_inventory_id` returns the existing credentials and does not
create a second initial scan. If the inventory loses a credential, use the rotation endpoint below.
Reusing an external ID with a changed repository URL updates the connection and queues an initial
scan for that repository.

## 2. Configure GitLab CI for rescans

In the GitLab project, configure:

- `VULN_SCAN_TRIGGER_URL`: the exact `trigger_url` from registration; regular CI variable.
- `VULN_SCAN_CI_TOKEN`: the returned `ci_token`; masked and protected as appropriate.

Example job (uses `jq` to safely encode branch names as JSON):

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

**Request**

```http
POST /api/v1/inventory/repositories/{application_id}/scans
Authorization: Bearer <application-ci-token>
Content-Type: application/json
```

```json
{
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "ref": "main",
  "event_id": "project-7:381:vuln-intel-scan"
}
```

`commit_sha` must be a full 40- or 64-character commit hash. `event_id` must be unique per
pipeline event and stable across retries of that event. A successful new request returns
`202 Accepted`; a retry of the same request returns `200 OK`. Reusing an event ID for a different
commit or ref returns `409 Conflict`. The API returns a scan ID and queues the work; it does not
wait for Trivy to finish.

The per-application token is valid only for that registered application's trigger and result-status
endpoint. It is separate from the inventory management token and GitLab PAT.

## 3. Callback delivery

Callbacks are `POST` requests with a JSON body and these headers:

```http
Content-Type: application/json
X-Vuln-Event-ID: <event_id>
X-Vuln-Signature: sha256=<lowercase-hex-hmac>
```

The signature is HMAC-SHA256 over the **exact raw UTF-8 request body**, using the registration's
`callback_secret`. Verify the signature before parsing JSON, compare it in constant time, and
deduplicate using `event_id`. Delivery is at least once; retries can therefore deliver the same
event more than once.

Successful scan payload (`scan.completed`):

```json
{
  "event_id": "...",
  "event_type": "scan.completed",
  "external_inventory_id": "asset-42",
  "application_id": "inventory:...",
  "scan": {
    "run_id": "...",
    "status": "succeeded",
    "commit_sha": "...",
    "ref": "main",
    "requested_at": "...",
    "started_at": "...",
    "completed_at": "...",
    "component_count": 120,
    "finding_count": 4,
    "unevaluated_count": 1,
    "findings": [
      {
        "vulnerability_id": "CVE-2025-0001",
        "canonical_id": "CVE-2025-0001",
        "ecosystem": "npm",
        "package_name": "example-package",
        "installed_version": "1.2.3",
        "fixed_version": "1.2.4",
        "severity": "HIGH",
        "sources": ["trivy", "vuln_intel"]
      }
    ]
  }
}
```

Terminal failures use `event_type: "scan.failed"`, `status: "failed"`, and include an `error`
summary. Transient worker failures are retried internally and do not send a failure callback until
the scan reaches a terminal state. Callback delivery retries indefinitely with capped exponential
backoff; return any 2xx response to acknowledge delivery. The receiver should keep processing
idempotent by `event_id`.

## 4. Check scan status

The CI credential for an application may fetch a scan result by ID:

```http
GET /api/v1/inventory/repositories/{application_id}/scans/{run_id}
Authorization: Bearer <application-ci-token>
```

The response contains the scan status, counts, findings, and unevaluated package matches. A scan
ID belonging to another application is returned as `404 Not Found`.

## 5. Rotate or revoke credentials

Rotate an application's CI trigger credential with the inventory management token:

```http
POST /api/v1/inventory/repositories/{application_id}/credential
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
```

The response contains the new `ci_token`; the old token is invalid immediately. Update the GitLab
CI/CD variable before the next pipeline runs.

Remove the inventory registration and repository connection:

```http
DELETE /api/v1/inventory/repositories/{application_id}
Authorization: Bearer <VULN_INVENTORY_API_TOKEN>
```

Removal revokes the application CI token and removes the connection from the UI. Existing scan
history remains available in **Application scans**.

## Errors

| Status | Meaning |
|---|---|
| `400 Bad Request` | Invalid JSON or request values, unsupported repository URL, or callback host not allowlisted. |
| `401 Unauthorized` | Missing or invalid inventory/application bearer token. |
| `404 Not Found` | Unknown application or scan ID. |
| `409 Conflict` | An idempotency event ID was reused for a different scan request. |
| `413 Payload Too Large` | Request body exceeds 16 KiB. |
| `415 Unsupported Media Type` | Request is not `application/json`. |
| `503 Service Unavailable` | Required API configuration, encryption key, or authentication is unavailable. |

## Operational and security notes

- Keep the dashboard and worker on the same PostgreSQL database and use the same stable
  `VULN_REPOSITORY_ENCRYPTION_KEY`.
- The inventory API token can register repositories and rotate/revoke application credentials.
  Keep it only in the inventory's secret store. CI jobs receive only their application's token.
- The worker uses one saved credential set per provider. The GitLab username and PAT are not sent
  to the external inventory.
- Restrict repository and callback hosts to exact trusted hostnames/IPs. Callback host allowlisting
  is enforced by the worker at registration and delivery.
- For a local IP deployment, use addresses routable from the actual GitLab runner and callback
  worker. A loopback address in a container refers to that container, not the host.
- Plain HTTP is supported only for configured self-hosted GitLab repository URLs and explicitly
  allowlisted callbacks. It exposes credentials or scan results to network observers; use it only
  on a trusted isolated network.
