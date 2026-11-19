"""External inventory registration, pipeline credentials, and signed result callbacks."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

from vuln_intel import config, repository_connections
from vuln_intel.database import _connect, _ensure_schema

log = logging.getLogger(__name__)
_EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_APPLICATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class IntegrationConflict(ValueError):
    pass


def inventory_token_is_valid(supplied: str) -> bool:
    expected = config.INVENTORY_API_TOKEN
    return bool(expected) and hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def validate_callback_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("callback_url is required.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("callback_url is malformed.") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed_hosts = {item.lower().rstrip(".") for item in config.INVENTORY_CALLBACK_HOSTS}
    if (parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.query or parsed.fragment
            or port not in (None, 443) or host not in allowed_hosts):
        raise ValueError("callback_url must use HTTPS on a host configured in VULN_INVENTORY_CALLBACK_HOSTS.")
    return parsed._replace(netloc=host).geturl()


def _public_api_base_url() -> str:
    value = config.PUBLIC_API_BASE_URL
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("VULN_PUBLIC_API_BASE_URL is invalid.") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or port not in (None, 443)):
        raise RuntimeError("VULN_PUBLIC_API_BASE_URL must be an HTTPS URL without credentials or query parameters.")
    return value.rstrip("/")


def _validate_registration(payload: dict) -> tuple[str, dict, str, str]:
    external_id = payload.get("external_inventory_id")
    if not isinstance(external_id, str) or not _EXTERNAL_ID.fullmatch(external_id):
        raise ValueError("external_inventory_id is required and must be 1–128 valid characters.")
    details = repository_connections.application_from_url(payload.get("repository_url"))
    name = payload.get("name", "")
    if not isinstance(name, str) or len(name) > 256:
        raise ValueError("name must be a string of at most 256 characters.")
    callback_url = validate_callback_url(payload.get("callback_url"))
    return external_id, details, name.strip() or details["name"], callback_url


def register_repository(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("The request body must be a JSON object.")
    external_id, details, name, callback_url = _validate_registration(payload)
    public_base = _public_api_base_url()
    repository_connections._fernet()

    # Check identity conflicts before updating the repository connection.
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            SELECT external_inventory_id, application_id
            FROM inventory_integrations
            WHERE external_inventory_id = %s OR application_id = %s
            """,
            (external_id, details["application_id"]),
        )
        existing = cur.fetchall()
    if any(row != (external_id, details["application_id"]) for row in existing):
        raise IntegrationConflict("This inventory ID or repository is already connected to a different integration.")

    repository = repository_connections.save_repository_connection(
        details["application_id"], details["repository_url"], name
    )
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            SELECT external_inventory_id, application_id, callback_url,
                   encrypted_pipeline_token, encrypted_callback_secret
            FROM inventory_integrations
            WHERE external_inventory_id = %s OR application_id = %s
            FOR UPDATE
            """,
            (external_id, details["application_id"]),
        )
        row = cur.fetchone()
        if row:
            if row[0] != external_id or row[1] != details["application_id"]:
                raise IntegrationConflict(
                    "This inventory ID or repository is already connected to a different integration."
                )
            pipeline_token = repository_connections._decrypt_secret(row[3])
            callback_secret = (
                repository_connections._decrypt_secret(row[4])
                if row[2] == callback_url
                else secrets.token_urlsafe(32)
            )
            cur.execute(
                """
                UPDATE inventory_integrations
                SET callback_url = %s, encrypted_callback_secret = %s, updated_at = now()
                WHERE external_inventory_id = %s
                """,
                (callback_url, repository_connections._encrypt_secret(callback_secret), external_id),
            )
            created = False
        else:
            pipeline_token = secrets.token_urlsafe(32)
            callback_secret = secrets.token_urlsafe(32)
            cur.execute(
                """
                INSERT INTO inventory_integrations
                    (external_inventory_id, application_id, callback_url,
                     encrypted_pipeline_token, pipeline_token_hash, encrypted_callback_secret)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    external_id,
                    details["application_id"],
                    callback_url,
                    repository_connections._encrypt_secret(pipeline_token),
                    hashlib.sha256(pipeline_token.encode("utf-8")).hexdigest(),
                    repository_connections._encrypt_secret(callback_secret),
                ),
            )
            created = True

    return {
        "repository": repository,
        "created": created,
        "callback": {"url": callback_url, "signing_secret": callback_secret},
        "pipeline": {
            "trigger_url": (
                f"{public_base}/api/v1/inventory/repositories/"
                f"{details['application_id']}/scans"
            ),
            "credential": pipeline_token,
            "authorization_header": "Authorization: Bearer <credential>",
            "request_body": {
                "commit_sha": "$CI_COMMIT_SHA",
                "ref": "$CI_COMMIT_REF_NAME",
                "event_id": "$CI_PIPELINE_ID",
            },
            "gitlab_ci_job": (
                "vulnerability-scan:\n"
                "  stage: test\n"
                "  script:\n"
                "    - >\n"
                "      curl --fail --silent --show-error --request POST \"$VULN_SCAN_TRIGGER_URL\"\n"
                "      --header \"Authorization: Bearer $VULN_SCAN_TRIGGER_TOKEN\"\n"
                "      --header \"Content-Type: application/json\"\n"
                "      --data \"{\\\"commit_sha\\\":\\\"$CI_COMMIT_SHA\\\","
                "\\\"ref\\\":\\\"$CI_COMMIT_REF_NAME\\\",\\\"event_id\\\":\\\"$CI_PIPELINE_ID\\\"}\""
            ),
        },
    }


def authenticate_pipeline(application_id: str, supplied_token: str) -> bool:
    if not isinstance(application_id, str) or not _APPLICATION_ID.fullmatch(application_id):
        return False
    if not isinstance(supplied_token, str) or not supplied_token:
        return False
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            "SELECT pipeline_token_hash FROM inventory_integrations WHERE application_id = %s",
            (application_id,),
        )
        row = cur.fetchone()
    if row is None:
        return False
    supplied_hash = hashlib.sha256(supplied_token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(supplied_hash, row[0])


def rotate_pipeline_credential(application_id: str) -> dict | None:
    if not isinstance(application_id, str) or not _APPLICATION_ID.fullmatch(application_id):
        raise ValueError("application_id must be a valid application ID.")
    public_base = _public_api_base_url()
    token = secrets.token_urlsafe(32)
    encrypted_token = repository_connections._encrypt_secret(token)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            UPDATE inventory_integrations
            SET encrypted_pipeline_token = %s, pipeline_token_hash = %s, updated_at = now()
            WHERE application_id = %s
            """,
            (encrypted_token, token_hash, application_id),
        )
        if cur.rowcount != 1:
            return None
    return {
        "trigger_url": (
            f"{public_base}/api/v1/inventory/repositories/{application_id}/scans"
        ),
        "credential": token,
    }


def enqueue_scan_callback(cur, Jsonb, run_id: str, application_id: str, payload: dict) -> None:
    cur.execute(
        """
        SELECT callback_url, encrypted_callback_secret
        FROM inventory_integrations
        WHERE application_id = %s
        """,
        (application_id,),
    )
    integration = cur.fetchone()
    if integration is None:
        return
    event_id = str(uuid.uuid4())
    callback_payload = {"event_id": event_id, **payload}
    cur.execute(
        """
        INSERT INTO inventory_callback_outbox
            (event_id, run_id, application_id, callback_url, encrypted_callback_secret, payload)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (run_id) DO NOTHING
        """,
        (event_id, run_id, application_id, integration[0], integration[1], Jsonb(callback_payload)),
    )


def claim_callback_delivery() -> dict | None:
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            WITH candidate AS (
                SELECT event_id
                FROM inventory_callback_outbox
                WHERE delivered_at IS NULL AND available_at <= now()
                ORDER BY created_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE inventory_callback_outbox AS item
            SET attempts = item.attempts + 1,
                available_at = now() + interval '1 minute'
            FROM candidate
            WHERE item.event_id = candidate.event_id
            RETURNING item.event_id, item.callback_url, item.encrypted_callback_secret,
                      item.payload, item.attempts
            """
        )
        row = cur.fetchone()
    if row is None:
        return None
    return dict(zip(("event_id", "callback_url", "encrypted_callback_secret", "payload", "attempts"), row))


def mark_callback_delivered(event_id: str) -> None:
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            UPDATE inventory_callback_outbox
            SET delivered_at = now(), last_error = NULL
            WHERE event_id = %s AND delivered_at IS NULL
            """,
            (event_id,),
        )


def retry_callback_delivery(event_id: str, error: str, attempts: int) -> None:
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            UPDATE inventory_callback_outbox
            SET available_at = now() + (least(3600, power(2, least(%s, 10)) * 10) * interval '1 second'),
                last_error = %s
            WHERE event_id = %s AND delivered_at IS NULL
            """,
            (attempts, error[:1000], event_id),
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def deliver_callback_once() -> bool:
    item = claim_callback_delivery()
    if item is None:
        return False
    try:
        validate_callback_url(item["callback_url"])
        secret = repository_connections._decrypt_secret(item["encrypted_callback_secret"])
        body = json.dumps(item["payload"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            item["callback_url"],
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Vuln-Event-ID": item["event_id"],
                "X-Vuln-Signature": f"sha256={signature}",
            },
            method="POST",
        )
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=15) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Callback endpoint returned HTTP {response.status}.")
    except (OSError, RuntimeError, TypeError, ValueError, urllib.error.URLError) as exc:
        log.warning("Inventory callback %s failed: %s", item["event_id"], exc)
        retry_callback_delivery(item["event_id"], f"{type(exc).__name__}: {exc}", item["attempts"])
        return True
    mark_callback_delivered(item["event_id"])
    log.info("Inventory callback %s delivered.", item["event_id"])
    return True
