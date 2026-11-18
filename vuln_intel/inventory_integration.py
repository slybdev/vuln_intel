"""External inventory registration, scoped CI credentials, and signed scan callbacks."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

from vuln_intel import config, database, repository_connections

_MAX_EXTERNAL_ID_LENGTH = 200
_MAX_CALLBACK_RESPONSE_SIZE = 4096


class IntegrationConfigurationError(RuntimeError):
    pass


def authenticate_inventory_api(supplied: str) -> bool:
    expected = config.INVENTORY_API_TOKEN
    return bool(expected) and hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def _validate_external_id(value):
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_EXTERNAL_ID_LENGTH:
        raise ValueError("external_inventory_id is required and must be at most 200 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("external_inventory_id must not contain control characters.")
    return value.strip()


def _validate_base_url():
    try:
        parsed = urlsplit(config.PUBLIC_API_BASE_URL.strip())
        _ = parsed.port
    except ValueError as exc:
        raise IntegrationConfigurationError("VULN_PUBLIC_API_BASE_URL is malformed.") from exc
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise IntegrationConfigurationError(
            "VULN_PUBLIC_API_BASE_URL must be an HTTP(S) origin without credentials or a path."
        )
    try:
        if ipaddress.ip_address(parsed.hostname).is_unspecified:
            raise IntegrationConfigurationError("VULN_PUBLIC_API_BASE_URL cannot use a wildcard address.")
    except ValueError:
        pass
    return config.PUBLIC_API_BASE_URL.rstrip("/")


def _validate_callback_url(value):
    if not isinstance(value, str):
        raise TypeError("callback_url must be a string.")
    try:
        parsed = urlsplit(value.strip())
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("callback_url is malformed.") from exc
    hostname = (parsed.hostname or "").lower().rstrip(".")
    allowed_hosts = {host.lower().rstrip(".") for host in config.INVENTORY_CALLBACK_HOSTS}
    try:
        is_unspecified = ipaddress.ip_address(hostname).is_unspecified
    except ValueError:
        is_unspecified = False
    if (parsed.scheme not in {"https", "http"} or not hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or hostname not in allowed_hosts or is_unspecified):
        raise ValueError("callback_url must use HTTP(S) and a host in VULN_INVENTORY_CALLBACK_HOSTS.")
    return parsed.geturl()


def _token():
    return "vint_ci_" + secrets.token_urlsafe(32)


def _callback_secret():
    return "vint_cb_" + secrets.token_urlsafe(32)


def _json_timestamp(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _application_id(external_inventory_id):
    digest = hashlib.sha256(external_inventory_id.encode("utf-8")).hexdigest()[:48]
    return f"inventory:{digest}"


def register_repository(payload):
    if not isinstance(payload, dict):
        raise TypeError("The request body must be a JSON object.")
    external_id = _validate_external_id(payload.get("external_inventory_id"))
    callback_url = _validate_callback_url(payload.get("callback_url"))
    base_url = _validate_base_url()
    details = repository_connections.repository_application_from_url(payload.get("repository_url"))
    name = payload.get("name", "")
    if not isinstance(name, str) or len(name) > 256:
        raise ValueError("name must be a string of at most 256 characters.")
    name = name.strip() or details["name"]
    application_id = _application_id(external_id)

    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (external_id,))
        cur.execute(
                """
                SELECT application_id, encrypted_ci_token, encrypted_callback_secret
                FROM inventory_integrations
                WHERE external_inventory_id = %s
                FOR UPDATE
                """,
                (external_id,),
        )
        existing = cur.fetchone()
        if existing and existing[0] != application_id:
            raise RuntimeError("Inventory registration is inconsistent; contact the service administrator.")
        if not existing:
            ci_token = _token()
            callback_secret = _callback_secret()
            encrypted_ci_token = repository_connections._encrypt_secret(ci_token)
            encrypted_callback_secret = repository_connections._encrypt_secret(callback_secret)
            token_hash = hashlib.sha256(ci_token.encode("utf-8")).digest()
            cur.execute(
                    """
                    INSERT INTO repository_connections (application_id, name, repository_url)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (application_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        repository_url = EXCLUDED.repository_url,
                        updated_at = now()
                    """,
                    (application_id, name, details["repository_url"]),
            )
            cur.execute(
                    """
                    INSERT INTO inventory_integrations
                        (external_inventory_id, application_id, callback_url, encrypted_ci_token,
                         ci_token_hash, encrypted_callback_secret)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (external_id, application_id, callback_url, encrypted_ci_token, token_hash,
                     encrypted_callback_secret),
            )
        else:
            ci_token = repository_connections._decrypt_secret(existing[1])
            callback_secret = repository_connections._decrypt_secret(existing[2])
            cur.execute(
                    """
                    UPDATE repository_connections
                    SET name = %s, repository_url = %s, updated_at = now()
                    WHERE application_id = %s
                    """,
                    (name, details["repository_url"], application_id),
            )
            cur.execute(
                    """
                    UPDATE inventory_integrations
                    SET callback_url = %s, updated_at = now()
                    WHERE external_inventory_id = %s
                    """,
                    (callback_url, external_id),
            )
    repository = {
        "application_id": application_id,
        "external_inventory_id": external_id,
        "name": name,
        "repository_url": details["repository_url"],
    }
    return {
        "repository": repository,
        "trigger_url": f"{base_url}/api/v1/inventory/repositories/{application_id}/scans",
        "ci_token": ci_token,
        "callback_secret": callback_secret,
    }


def authenticate_ci_credential(application_id, supplied):
    if not isinstance(supplied, str) or not supplied:
        return False
    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
        cur.execute("SELECT ci_token_hash FROM inventory_integrations WHERE application_id = %s",
                    (application_id,))
        row = cur.fetchone()
    if not row:
        return False
    actual = hashlib.sha256(supplied.encode("utf-8")).digest()
    return hmac.compare_digest(bytes(row[0]), actual)


def rotate_ci_credential(application_id):
    new_token = _token()
    encrypted_token = repository_connections._encrypt_secret(new_token)
    token_hash = hashlib.sha256(new_token.encode("utf-8")).digest()
    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
        cur.execute(
            """
            UPDATE inventory_integrations
            SET encrypted_ci_token = %s, ci_token_hash = %s, updated_at = now()
            WHERE application_id = %s
            RETURNING external_inventory_id
            """,
            (encrypted_token, token_hash, application_id),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {"external_inventory_id": row[0], "ci_token": new_token}


def remove_registration(application_id):
    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
        cur.execute(
            "SELECT external_inventory_id FROM inventory_integrations WHERE application_id = %s",
            (application_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        cur.execute("DELETE FROM repository_connections WHERE application_id = %s", (application_id,))
    return row[0]


def get_registration_for_application(application_id):
    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
        cur.execute(
                """
                SELECT external_inventory_id, application_id, callback_url
                FROM inventory_integrations WHERE application_id = %s
                """,
                (application_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {"external_inventory_id": row[0], "application_id": row[1], "callback_url": row[2]}


def enqueue_scan_callback(cur, Jsonb, scan, event_type, findings=None, error=None):
    cur.execute(
        """
        SELECT external_inventory_id, callback_url, encrypted_callback_secret
        FROM inventory_integrations
        WHERE application_id = %s
        """,
        (scan["application_id"],),
    )
    integration = cur.fetchone()
    if not integration:
        return
    external_id, callback_url, encrypted_secret = integration
    event_id = str(uuid.uuid4())
    payload = {
        "event_id": event_id,
        "event_type": event_type,
        "external_inventory_id": external_id,
        "application_id": scan["application_id"],
        "scan": {
            "run_id": scan["run_id"],
            "status": scan["status"],
            "commit_sha": scan["commit_sha"],
            "ref": scan["ref"],
            "requested_at": _json_timestamp(scan.get("requested_at")),
            "started_at": _json_timestamp(scan.get("started_at")),
            "completed_at": _json_timestamp(scan.get("completed_at")),
            "component_count": scan.get("component_count", 0),
            "finding_count": scan.get("finding_count", 0),
            "unevaluated_count": scan.get("unevaluated_count", 0),
            "findings": findings or [],
        },
    }
    if error:
        payload["scan"]["error"] = error[:1000]
    cur.execute(
        """
        INSERT INTO inventory_callback_outbox
            (event_id, scan_run_id, event_type, callback_url, encrypted_signing_secret, payload)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (scan_run_id, event_type) DO NOTHING
        """,
        (event_id, scan["run_id"], event_type, callback_url, encrypted_secret, Jsonb(payload)),
    )


def claim_callback():
    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
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
                    available_at = now() + interval '2 minutes'
                FROM candidate
                WHERE item.event_id = candidate.event_id
                RETURNING item.event_id, item.callback_url, item.encrypted_signing_secret,
                          item.payload, item.attempts
                """
        )
        row = cur.fetchone()
    if not row:
        return None
    return dict(zip(("event_id", "callback_url", "encrypted_signing_secret", "payload", "attempts"), row))


def finish_callback(event_id, error=None):
    conn, _ = database._connect()
    with conn, conn.cursor() as cur:
        database._ensure_schema(cur)
        if error is None:
            cur.execute(
                """
                UPDATE inventory_callback_outbox
                SET delivered_at = now(), last_error = NULL
                WHERE event_id = %s AND delivered_at IS NULL
                """,
                (event_id,),
            )
        else:
            cur.execute(
                """
                UPDATE inventory_callback_outbox
                SET available_at = now() + (least(3600, 15 * power(2, least(attempts, 8))) * interval '1 second'),
                    last_error = %s
                WHERE event_id = %s AND delivered_at IS NULL
                """,
                (error[:1000], event_id),
            )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def deliver_callback_once():
    item = claim_callback()
    if not item:
        return False
    try:
        _validate_callback_url(item["callback_url"])
        secret = repository_connections._decrypt_secret(item["encrypted_signing_secret"])
        body = json.dumps(item["payload"], ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            item["callback_url"],
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Vuln-Event-ID": item["event_id"],
                "X-Vuln-Signature": f"sha256={signature}",
            },
        )
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=15) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Callback endpoint returned HTTP {response.status}.")
            response.read(_MAX_CALLBACK_RESPONSE_SIZE)
        finish_callback(item["event_id"])
    except (OSError, RuntimeError, ValueError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        finish_callback(item["event_id"], f"{type(exc).__name__}: {exc}")
    return True
