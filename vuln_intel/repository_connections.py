"""Repository connection storage with encrypted access credentials."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from urllib.parse import unquote, urlsplit

from vuln_intel import config, event_store
from vuln_intel.database import _connect, _ensure_schema

_APPLICATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_ACCESS_TOKEN_LENGTH = 4096
_GITHUB_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
_GITLAB_SEGMENT = re.compile(r"[A-Za-z0-9._-]{1,255}\Z")


class RepositoryEncryptionError(RuntimeError):
    pass


class RepositoryNotFound(RuntimeError):
    pass


class ProviderCredentialVerificationError(ValueError):
    pass


class ProviderCredentialVerificationUnavailable(RuntimeError):
    pass


def _verify_github_credentials(username: str, token: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "vuln-intel",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            profile = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        status = exc.code
        rate_limit_remaining = getattr(exc.headers, "get", lambda *_: None)("X-RateLimit-Remaining")
        exc.close()
        if status == 401:
            raise ProviderCredentialVerificationError(
                "GitHub rejected this token. Check that it is active and copied correctly."
            ) from exc
        if status == 403 and rate_limit_remaining == "0":
            raise ProviderCredentialVerificationUnavailable(
                "GitHub's API rate limit prevented verification. Wait a moment and try again."
            ) from exc
        if status == 403:
            raise ProviderCredentialVerificationError(
                "GitHub denied token verification. Check the token and any required organization SSO authorization."
            ) from exc
        if status == 429 or status >= 500:
            raise ProviderCredentialVerificationUnavailable(
                f"GitHub is temporarily unavailable (HTTP {status}); credentials were not saved."
            ) from exc
        raise ProviderCredentialVerificationError(
            f"GitHub could not verify this token (HTTP {status})."
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderCredentialVerificationUnavailable(
            "Could not reach GitHub to verify the token; credentials were not saved."
        ) from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProviderCredentialVerificationUnavailable(
            "GitHub returned an invalid response; credentials were not saved."
        ) from exc

    account = profile.get("login") if isinstance(profile, dict) else None
    if not isinstance(account, str) or not account:
        raise ProviderCredentialVerificationUnavailable(
            "GitHub returned an invalid account response; credentials were not saved."
        )
    if account.casefold() != username.casefold():
        raise ProviderCredentialVerificationError(
            f"This token authenticates as @{account}, not @{username}. Check the username and token."
        )
    return {"status": "verified"}


def validate_repository_url(repository_url: str) -> str:
    if not isinstance(repository_url, str):
        raise TypeError("Repository URL must be a string.")
    try:
        parsed = urlsplit(repository_url.strip())
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Repository URL is malformed.") from exc
    allowed_hosts = {host.lower() for host in config.REPOSITORY_HOSTS}
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or port not in (None, 443)
            or parsed.hostname.lower() not in allowed_hosts):
        raise ValueError("Repository URL must use HTTPS and an allowed repository host.")
    if not parsed.path.strip("/") or any(part in {".", ".."} for part in parsed.path.split("/")):
        raise ValueError("Repository URL has an invalid path.")
    return parsed._replace(query="", fragment="").geturl().rstrip("/")


def _fernet():
    if not config.REPOSITORY_ENCRYPTION_KEY:
        raise RepositoryEncryptionError(
            "VULN_REPOSITORY_ENCRYPTION_KEY is required to save Git provider credentials."
        )
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise RepositoryEncryptionError("Git credential encryption support is not installed.") from exc
    try:
        return Fernet(config.REPOSITORY_ENCRYPTION_KEY.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RepositoryEncryptionError("VULN_REPOSITORY_ENCRYPTION_KEY is invalid.") from exc


def _encrypt_secret(secret: str | None) -> bytes | None:
    if not secret:
        return None
    return _fernet().encrypt(secret.encode("utf-8"))


def _decrypt_secret(encrypted_secret: bytes | None) -> str:
    if not encrypted_secret:
        return ""
    try:
        from cryptography.fernet import InvalidToken
    except ImportError as exc:
        raise RepositoryEncryptionError("Git credential encryption support is not installed.") from exc
    try:
        return _fernet().decrypt(bytes(encrypted_secret)).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise RepositoryEncryptionError(
            "Could not decrypt repository credentials; verify VULN_REPOSITORY_ENCRYPTION_KEY."
        ) from exc


def _normalize_application_id(application_id: str) -> str:
    if not isinstance(application_id, str):
        raise TypeError("Application ID must be a string.")
    if not _APPLICATION_ID.fullmatch(application_id):
        raise ValueError("Application ID must be 1–128 letters, digits, dots, underscores, colons, or hyphens.")
    return application_id


def provider_for_repository(repository_url: str) -> str:
    validated_url = validate_repository_url(repository_url)
    hostname = urlsplit(validated_url).hostname.lower()
    if hostname == "github.com":
        return "github"
    return "gitlab"


def github_application_from_url(repository_url: str) -> dict:
    validated_url = validate_repository_url(repository_url)
    parsed = urlsplit(validated_url)
    if parsed.hostname.lower() != "github.com":
        raise ValueError("Enter a GitHub repository URL.")
    parts = [unquote(part) for part in parsed.path.strip("/").split("/")]
    if len(parts) != 2:
        raise ValueError("Enter the repository root URL, such as https://github.com/owner/repository.")
    owner, repository = parts
    repository = re.sub(r"\.git$", "", repository, flags=re.IGNORECASE)
    if (not _GITHUB_OWNER.fullmatch(owner) or not _GITHUB_REPOSITORY.fullmatch(repository)
            or repository in {".", ".."}):
        raise ValueError("The GitHub repository URL has an invalid owner or repository name.")

    identity = f"{owner.lower()}:{repository.lower()}"
    application_id = f"github:{identity}"
    if len(application_id) > 128:
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        application_id = f"{application_id[:115]}:{suffix}"
    return {
        "application_id": application_id,
        "name": f"{owner}/{repository}",
        "repository_url": f"https://github.com/{owner}/{repository}",
    }


def gitlab_application_from_url(repository_url: str) -> dict:
    validated_url = validate_repository_url(repository_url)
    parsed = urlsplit(validated_url)
    if parsed.hostname.lower() == "github.com":
        raise ValueError("Enter a GitLab repository URL.")
    parts = [unquote(part) for part in parsed.path.strip("/").split("/")]
    if len(parts) < 2:
        raise ValueError("Enter the GitLab repository root URL, including its group and project.")
    project = re.sub(r"\.git$", "", parts[-1], flags=re.IGNORECASE)
    namespace = parts[:-1]
    if any(
        not _GITLAB_SEGMENT.fullmatch(part) or part in {".", ".."}
        for part in [*namespace, project]
    ):
        raise ValueError("The GitLab repository URL has an invalid group or project path.")

    host = parsed.hostname.lower()
    identity = f"{host}:{':'.join(part.lower() for part in namespace)}:{project.lower()}"
    application_id = f"gitlab:{identity}"
    if len(application_id) > 128:
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        application_id = f"gitlab:{host[:40]}:{suffix}"
    return {
        "application_id": application_id,
        "name": "/".join([*namespace, project]),
        "repository_url": f"https://{host}/{'/'.join([*namespace, project])}",
    }


def application_from_url(repository_url: str) -> dict:
    validated_url = validate_repository_url(repository_url)
    if urlsplit(validated_url).hostname.lower() == "github.com":
        return github_application_from_url(validated_url)
    return gitlab_application_from_url(validated_url)


def save_provider_credentials(provider: str, username: str, password: str):
    if provider not in {"github", "gitlab"}:
        raise ValueError("Provider must be github or gitlab.")
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("Provider username and token must be strings.")
    if not username:
        raise ValueError("Provide a username.")
    if len(username) > _MAX_ACCESS_TOKEN_LENGTH or len(password) > _MAX_ACCESS_TOKEN_LENGTH:
        raise ValueError("Provider username and token must each be at most 4096 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in username + password):
        raise ValueError("Provider credentials must not contain control characters.")
    encrypted_username = _encrypt_secret(username)
    password_to_verify = password
    current_password = None
    verification = None
    if provider == "github":
        if not password:
            conn, _ = _connect()
            with conn, conn.cursor() as cur:
                _ensure_schema(cur)
                cur.execute(
                    "SELECT encrypted_password FROM git_provider_credentials WHERE provider = %s",
                    (provider,),
                )
                existing = cur.fetchone()
            if existing is None:
                raise ValueError("Provide a personal access token to configure this provider.")
            current_password = bytes(existing[0])
            password_to_verify = _decrypt_secret(current_password)
            if not password_to_verify:
                raise ValueError("Provide a personal access token to configure this provider.")
        verification = _verify_github_credentials(username, password_to_verify)

    conn, Jsonb = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            "SELECT encrypted_password FROM git_provider_credentials WHERE provider = %s FOR UPDATE",
            (provider,),
        )
        current = cur.fetchone()
        if not password and current is None:
            raise ValueError("Provide a personal access token to configure this provider.")
        if not password and current_password is not None and bytes(current[0]) != current_password:
            raise ProviderCredentialVerificationError(
                "The saved GitHub token changed during verification. Try saving again."
            )
        encrypted_password = _encrypt_secret(password) if password else current[0]
        cur.execute(
            """
            INSERT INTO git_provider_credentials (provider, encrypted_username, encrypted_password)
            VALUES (%s, %s, %s)
            ON CONFLICT (provider) DO UPDATE SET
                encrypted_username = EXCLUDED.encrypted_username,
                encrypted_password = EXCLUDED.encrypted_password,
                updated_at = now()
            RETURNING provider, updated_at
            """,
            (provider, encrypted_username, encrypted_password),
        )
        row = cur.fetchone()
        event_store.insert_event(
            cur,
            Jsonb,
            severity="INFO",
            category="settings",
            event_type="provider_credentials.configured",
            source="Git provider settings",
            message=f"{provider.title()} provider credentials configured",
            target_type="provider",
            target_id=provider,
            outcome="updated" if current else "succeeded",
            actor="local_operator",
            details={"provider": provider},
        )
    credentials = {"provider": row[0], "configured": True, "updated_at": row[1]}
    if verification:
        credentials["verification"] = verification
    return credentials


def list_provider_credentials() -> list[dict]:
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute("SELECT provider, updated_at FROM git_provider_credentials ORDER BY provider")
        rows = cur.fetchall()
    configured = {provider: updated_at for provider, updated_at in rows}
    return [
        {"provider": provider, "configured": provider in configured, "updated_at": configured.get(provider)}
        for provider in ("github", "gitlab")
    ]


def get_provider_credentials(repository_url: str) -> dict:
    provider = provider_for_repository(repository_url)
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            "SELECT encrypted_username, encrypted_password FROM git_provider_credentials WHERE provider = %s",
            (provider,),
        )
        row = cur.fetchone()
    if row is None:
        return {"provider": provider, "username": "", "password": ""}
    return {
        "provider": provider,
        "username": _decrypt_secret(row[0]),
        "password": _decrypt_secret(row[1]),
    }


def delete_provider_credentials(provider: str) -> bool:
    if provider not in {"github", "gitlab"}:
        raise ValueError("Provider must be github or gitlab.")
    conn, Jsonb = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            "DELETE FROM git_provider_credentials WHERE provider = %s RETURNING provider",
            (provider,),
        )
        row = cur.fetchone()
        if row:
            event_store.insert_event(
                cur,
                Jsonb,
                severity="MEDIUM",
                category="settings",
                event_type="provider_credentials.removed",
                source="Git provider settings",
                message=f"{provider.title()} provider credentials removed",
                target_type="provider",
                target_id=provider,
                outcome="deleted",
                actor="local_operator",
                details={"provider": provider},
            )
        deleted = row is not None
    return deleted


def save_repository_connection(application_id: str, repository_url: str, name: str = ""):
    application_id = _normalize_application_id(application_id)
    repository_url = validate_repository_url(repository_url)
    if not isinstance(name, str):
        raise TypeError("Repository name must be a string.")
    if len(name) > 256:
        raise ValueError("Repository name must be at most 256 characters.")
    normalized_name = name.strip() or application_id

    conn, Jsonb = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            "SELECT 1 FROM repository_connections WHERE application_id = %s FOR UPDATE",
            (application_id,),
        )
        is_existing = cur.fetchone() is not None
        cur.execute(
            """
            INSERT INTO repository_connections
                (application_id, name, repository_url)
            VALUES (%s, %s, %s)
            ON CONFLICT (application_id) DO UPDATE SET
                name = EXCLUDED.name,
                repository_url = EXCLUDED.repository_url,
                updated_at = now()
            RETURNING application_id, name, repository_url, updated_at
            """,
            (application_id, normalized_name, repository_url),
        )
        row = cur.fetchone()
        event_store.insert_event(
            cur,
            Jsonb,
            severity="INFO",
            category="repository",
            event_type="repository.updated" if is_existing else "repository.connected",
            source="Repository inventory",
            message=f"Repository {'updated' if is_existing else 'connected'}: {normalized_name}",
            target_type="repository",
            target_id=application_id,
            outcome="updated" if is_existing else "succeeded",
            actor="local_operator",
            details={"repository_url": repository_url},
        )
    return dict(zip(("application_id", "name", "repository_url", "updated_at"), row))


def list_repository_connections() -> list[dict]:
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            SELECT application_id, name, repository_url, updated_at
            FROM repository_connections
            ORDER BY name, application_id
            """
        )
        rows = cur.fetchall()
    columns = ("application_id", "name", "repository_url", "updated_at")
    return [dict(zip(columns, row)) for row in rows]


def get_repository_connection(application_id: str) -> dict:
    application_id = _normalize_application_id(application_id)
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            SELECT application_id, name, repository_url
            FROM repository_connections
            WHERE application_id = %s
            """,
            (application_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise RepositoryNotFound(f"No repository is connected for application {application_id}.")
    return {
        "application_id": row[0],
        "name": row[1],
        "repository_url": validate_repository_url(row[2]),
    }


def delete_repository_connection(application_id: str) -> bool:
    application_id = _normalize_application_id(application_id)
    conn, Jsonb = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            "DELETE FROM inventory_integrations WHERE application_id = %s",
            (application_id,),
        )
        cur.execute(
            "DELETE FROM repository_connections WHERE application_id = %s RETURNING name",
            (application_id,),
        )
        row = cur.fetchone()
        if row:
            event_store.insert_event(
                cur,
                Jsonb,
                severity="MEDIUM",
                category="repository",
                event_type="repository.disconnected",
                source="Repository inventory",
                message=f"Repository disconnected: {row[0]}",
                target_type="repository",
                target_id=application_id,
                outcome="deleted",
                actor="local_operator",
            )
        deleted = row is not None
    return deleted
