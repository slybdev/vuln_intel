"""Local web dashboard and loopback-only repository settings API."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import mimetypes
import re
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote
from wsgiref.simple_server import make_server

from vuln_intel import config, dashboard_data, inventory_integration, repository_connections, scan_service, scan_store

log = logging.getLogger(__name__)
WEB_DIR = Path(__file__).with_name("web")
MAX_PAGE_SIZE = 100
MAX_SCAN_REQUEST_SIZE = 16 * 1024


def _local_settings_access_failure(environ, start_response):
    try:
        is_loopback = ipaddress.ip_address(environ.get("REMOTE_ADDR") or "").is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        return _json_response(
            start_response, "403 Forbidden",
            {"error": "Repository settings can only be managed from localhost."},
        )
    return None


def _json_response(start_response, status, payload):
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    start_response(status, [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ])
    return [body]


def _bearer_token(environ):
    scheme, separator, token = environ.get("HTTP_AUTHORIZATION", "").partition(" ")
    if not separator or scheme.casefold() != "bearer":
        return ""
    return token.strip()


def _read_json_request(environ, start_response):
    if environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != "application/json":
        return None, _json_response(start_response, "415 Unsupported Media Type", {"error": "Content-Type must be application/json."})
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        return None, _json_response(start_response, "400 Bad Request", {"error": "Invalid Content-Length."})
    if length <= 0 or length > MAX_SCAN_REQUEST_SIZE:
        return None, _json_response(start_response, "413 Payload Too Large", {"error": "Request body must be between 1 byte and 16 KiB."})
    try:
        payload = json.loads(environ["wsgi.input"].read(length))
    except (ValueError, KeyError):
        return None, _json_response(start_response, "400 Bad Request", {"error": "Request body must contain valid JSON."})
    return payload, None


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    if path == "/api/repositories/scan" and method == "POST":
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
        try:
            details = repository_connections.repository_application_from_url(payload.get("repository_url"))
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        try:
            connection = repository_connections.save_repository_connection(
                details["application_id"], details["repository_url"], details["name"]
            )
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not save repository from scan request.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Repository could not be added."})
        try:
            run, created = scan_service.request_latest_scan(connection["application_id"])
        except Exception:
            log.exception("Repository %s was added, but its scan could not be queued.", connection["application_id"])
            return _json_response(
                start_response, "500 Internal Server Error",
                {"error": "Repository was added, but the scan could not be queued."},
            )
        return _json_response(start_response, "202 Accepted" if created else "200 OK", {
            "repository": connection,
            "scan": run,
            "created": created,
        })
    if path.startswith("/api/repositories/") and path.endswith("/scan") and method == "POST":
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        application_id = unquote(path[len("/api/repositories/"):-len("/scan")].strip("/"))
        try:
            repository_connections.get_repository_connection(application_id)
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except repository_connections.RepositoryNotFound as exc:
            return _json_response(start_response, "404 Not Found", {"error": str(exc)})
        except Exception:
            log.exception("Could not check repository before manual scan request.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Repository could not be loaded."})
        try:
            run, created = scan_service.request_latest_scan(application_id)
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        return _json_response(start_response, "202 Accepted" if created else "200 OK", {
            "scan": run,
            "created": created,
        })
    if path == "/api/git-credentials":
        if method not in {"GET", "POST"}:
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        if method == "GET":
            try:
                return _json_response(start_response, "200 OK", {
                    "items": repository_connections.list_provider_credentials(),
                })
            except Exception:
                log.exception("Could not list Git provider credentials.")
                return _json_response(start_response, "500 Internal Server Error", {"error": "Git provider credentials could not be loaded."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
        try:
            credentials = repository_connections.save_provider_credentials(
                payload.get("provider"), payload.get("username"), payload.get("token")
            )
        except repository_connections.ProviderCredentialVerificationError as exc:
            return _json_response(start_response, "422 Unprocessable Entity", {"error": str(exc)})
        except repository_connections.ProviderCredentialVerificationUnavailable as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except repository_connections.RepositoryEncryptionError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except Exception:
            log.exception("Could not save Git provider credentials.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Git provider credentials could not be saved."})
        return _json_response(start_response, "200 OK", {"credentials": credentials})
    if path.startswith("/api/git-credentials/") and method == "DELETE":
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        provider = unquote(path[len("/api/git-credentials/"):])
        try:
            deleted = repository_connections.delete_provider_credentials(provider)
        except ValueError as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not delete Git provider credentials.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Git provider credentials could not be deleted."})
        if not deleted:
            return _json_response(start_response, "404 Not Found", {"error": "Git provider credentials not found."})
        return _json_response(start_response, "200 OK", {"deleted": True})
    if path == "/api/repositories":
        if method not in {"GET", "POST"}:
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        if method == "GET":
            try:
                return _json_response(start_response, "200 OK", {
                    "items": repository_connections.list_repository_connections(),
                })
            except Exception:
                log.exception("Could not list repository connections.")
                return _json_response(start_response, "500 Internal Server Error", {"error": "Repository connections could not be loaded."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
        try:
            connection = repository_connections.save_repository_connection(
                payload.get("application_id"),
                payload.get("repository_url"),
                payload.get("name", ""),
            )
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except repository_connections.RepositoryEncryptionError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except Exception:
            log.exception("Could not save repository connection.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Repository connection could not be saved."})
        return _json_response(start_response, "200 OK", {"repository": connection})
    if path.startswith("/api/repositories/") and method == "DELETE":
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        application_id = unquote(path[len("/api/repositories/"):])
        try:
            deleted = repository_connections.delete_repository_connection(application_id)
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not delete repository connection.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Repository connection could not be deleted."})
        if not deleted:
            return _json_response(start_response, "404 Not Found", {"error": "Repository connection not found."})
        return _json_response(start_response, "200 OK", {"deleted": True})
    if path == "/api/v1/inventory/repositories" and method == "POST":
        if not config.INVENTORY_API_TOKEN:
            return _json_response(start_response, "503 Service Unavailable", {"error": "Inventory API authentication is not configured."})
        if not config.PUBLIC_API_BASE_URL or not config.REPOSITORY_ENCRYPTION_KEY:
            return _json_response(start_response, "503 Service Unavailable", {"error": "Inventory API configuration is incomplete."})
        if not config.INVENTORY_CALLBACK_HOSTS:
            return _json_response(start_response, "503 Service Unavailable", {"error": "Inventory callback host allowlist is not configured."})
        if not inventory_integration.authenticate_inventory_api(_bearer_token(environ)):
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid inventory bearer authentication is required."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        try:
            registration = inventory_integration.register_repository(payload)
            run, created = scan_service.request_inventory_initial_scan(
                registration["repository"]["application_id"],
                registration["repository"]["external_inventory_id"],
                registration["repository"]["repository_url"],
            )
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except inventory_integration.IntegrationConfigurationError as exc:
            log.error("External inventory configuration error: %s", exc)
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except repository_connections.RepositoryEncryptionError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except Exception:
            log.exception("Could not register external inventory repository.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Repository registration or initial scan request failed."})
        return _json_response(start_response, "202 Accepted" if created else "200 OK", {
            **registration,
            "scan": run,
            "created": created,
        })
    inventory_scan_match = re.fullmatch(
        r"/api/v1/inventory/repositories/([^/]+)/scans(?:/([0-9a-fA-F-]{36}))?",
        path,
    )
    if inventory_scan_match and method in {"GET", "POST"}:
        application_id = unquote(inventory_scan_match.group(1))
        try:
            authenticated = inventory_integration.authenticate_ci_credential(
                application_id, _bearer_token(environ))
        except Exception:
            log.exception("Could not authenticate inventory scan request for %s.", application_id)
            return _json_response(start_response, "500 Internal Server Error", {"error": "Inventory credentials could not be checked."})
        if not authenticated:
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid application bearer authentication is required."})
        if method == "POST" and inventory_scan_match.group(2) is None:
            payload, error = _read_json_request(environ, start_response)
            if error:
                return error
            if not isinstance(payload, dict):
                return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
            if payload.get("application_id") not in (None, application_id):
                return _json_response(start_response, "400 Bad Request", {"error": "application_id must match the repository path."})
            try:
                run, created = scan_service.request_scan({**payload, "application_id": application_id})
            except scan_store.IdempotencyConflict as exc:
                return _json_response(start_response, "409 Conflict", {"error": str(exc)})
            except (TypeError, ValueError) as exc:
                return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
            except Exception:
                log.exception("Could not queue inventory scan for %s.", application_id)
                return _json_response(start_response, "500 Internal Server Error", {"error": "Scan request could not be queued."})
            return _json_response(start_response, "202 Accepted" if created else "200 OK", {
                "scan": run,
                "created": created,
            })
        if method == "GET" and inventory_scan_match.group(2):
            run_id = inventory_scan_match.group(2)
            try:
                run_id = str(uuid.UUID(run_id))
            except ValueError:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid scan ID."})
            try:
                run = scan_store.get_scan_run(run_id)
            except Exception:
                log.exception("Could not load inventory scan %s.", run_id)
                return _json_response(start_response, "500 Internal Server Error", {"error": "Scan results could not be loaded."})
            if run is None or run["application_id"] != application_id:
                return _json_response(start_response, "404 Not Found", {"error": "Scan not found."})
            return _json_response(start_response, "200 OK", run)
        return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
    inventory_credential_match = re.fullmatch(
        r"/api/v1/inventory/repositories/([^/]+)/credential",
        path,
    )
    if inventory_credential_match and method == "POST":
        if not config.INVENTORY_API_TOKEN:
            return _json_response(start_response, "503 Service Unavailable", {"error": "Inventory API authentication is not configured."})
        if not inventory_integration.authenticate_inventory_api(_bearer_token(environ)):
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid inventory bearer authentication is required."})
        application_id = unquote(inventory_credential_match.group(1))
        try:
            credential = inventory_integration.rotate_ci_credential(application_id)
        except repository_connections.RepositoryEncryptionError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except Exception:
            log.exception("Could not rotate inventory credential for %s.", application_id)
            return _json_response(start_response, "500 Internal Server Error", {"error": "Inventory credential could not be rotated."})
        if credential is None:
            return _json_response(start_response, "404 Not Found", {"error": "Inventory repository not found."})
        return _json_response(start_response, "200 OK", credential)
    inventory_repository_match = re.fullmatch(
        r"/api/v1/inventory/repositories/([^/]+)",
        path,
    )
    if inventory_repository_match and method == "DELETE":
        if not config.INVENTORY_API_TOKEN:
            return _json_response(start_response, "503 Service Unavailable", {"error": "Inventory API authentication is not configured."})
        if not inventory_integration.authenticate_inventory_api(_bearer_token(environ)):
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid inventory bearer authentication is required."})
        application_id = unquote(inventory_repository_match.group(1))
        try:
            external_id = inventory_integration.remove_registration(application_id)
        except Exception:
            log.exception("Could not remove inventory repository %s.", application_id)
            return _json_response(start_response, "500 Internal Server Error", {"error": "Inventory repository could not be removed."})
        if external_id is None:
            return _json_response(start_response, "404 Not Found", {"error": "Inventory repository not found."})
        return _json_response(start_response, "200 OK", {"removed": True, "external_inventory_id": external_id})
    if path == "/api/scans" and method == "POST":
        if not config.SCAN_API_TOKEN:
            return _json_response(start_response, "503 Service Unavailable", {"error": "Scan API authentication is not configured."})
        expected = f"Bearer {config.SCAN_API_TOKEN}"
        supplied = environ.get("HTTP_AUTHORIZATION", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid bearer authentication is required."})
        if environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != "application/json":
            return _json_response(start_response, "415 Unsupported Media Type", {"error": "Content-Type must be application/json."})
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            return _json_response(start_response, "400 Bad Request", {"error": "Invalid Content-Length."})
        if length <= 0 or length > MAX_SCAN_REQUEST_SIZE:
            return _json_response(start_response, "413 Payload Too Large", {"error": "Request body must be between 1 byte and 16 KiB."})
        try:
            payload = json.loads(environ["wsgi.input"].read(length))
        except (ValueError, KeyError):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must contain valid JSON."})
        try:
            run, created = scan_service.request_scan(payload)
        except scan_store.IdempotencyConflict as exc:
            return _json_response(start_response, "409 Conflict", {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        return _json_response(start_response, "202 Accepted" if created else "200 OK", {
            "scan": run,
            "created": created,
        })
    if method != "GET":
        return _json_response(start_response, "405 Method Not Allowed", {"error": "Only GET is supported."})
    try:
        if path == "/api/scans":
            params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
            application_id = params.get("application_id", [""])[0].strip()
            if len(application_id) > 128:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid application_id."})
            limit = min(MAX_PAGE_SIZE, max(1, int(params.get("limit", ["50"])[0])))
            return _json_response(start_response, "200 OK", {
                "items": scan_store.list_scan_runs(application_id, limit),
            })
        if path.startswith("/api/scans/"):
            raw_id = unquote(path[len("/api/scans/"):])
            try:
                run_id = str(uuid.UUID(raw_id))
            except (ValueError, AttributeError):
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid scan ID."})
            run = scan_store.get_scan_run(run_id)
            if run is None:
                return _json_response(start_response, "404 Not Found", {"error": "Scan not found."})
            return _json_response(start_response, "200 OK", run)
        if path.startswith("/api/applications/") and path.endswith("/findings"):
            raw_id = unquote(path[len("/api/applications/"):-len("/findings")].strip("/"))
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", raw_id):
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid application_id."})
            params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
            ref = params.get("ref", [""])[0][:255]
            status = params.get("status", ["active"])[0]
            if status not in {"", "active", "resolved"}:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid finding status."})
            return _json_response(start_response, "200 OK", {
                "items": scan_store.list_application_findings(raw_id, ref, status),
            })
        if path == "/api/trends":
            return _json_response(start_response, "200 OK", dashboard_data.get_publication_trends())
        if path == "/api/summary":
            return _json_response(start_response, "200 OK", dashboard_data.get_summary())
        if path == "/api/status":
            return _json_response(start_response, "200 OK", dashboard_data.get_pipeline_status())
        if path == "/api/vulnerabilities":
            params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
            page = max(1, int(params.get("page", ["1"])[0]))
            page_size = min(MAX_PAGE_SIZE, max(1, int(params.get("page_size", ["20"])[0])))
            severity = params.get("severity", [""])[0].upper()
            allowed = {"", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
            if severity not in allowed:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid severity filter."})
            query = params.get("q", [""])[0].strip()[:200]
            exploited = params.get("exploited", [""])[0].lower() in {"1", "true", "yes"}
            result = dashboard_data.list_vulnerabilities(query, severity, exploited, page, page_size)
            return _json_response(start_response, "200 OK", result)
        if path.startswith("/api/vulnerabilities/"):
            identifier = unquote(path[len("/api/vulnerabilities/"):])
            if not identifier or len(identifier) > 160:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid vulnerability identifier."})
            vulnerability = dashboard_data.get_vulnerability(identifier)
            if vulnerability is None:
                return _json_response(start_response, "404 Not Found", {"error": "Vulnerability not found."})
            return _json_response(start_response, "200 OK", vulnerability)
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        candidate = (WEB_DIR / relative).resolve()
        if WEB_DIR.resolve() not in candidate.parents or not candidate.is_file():
            return _json_response(start_response, "404 Not Found", {"error": "Not found."})
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        start_response("200 OK", [
            ("Content-Type", f"{content_type}; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("X-Content-Type-Options", "nosniff"),
        ])
        return [body]
    except (ValueError, IndexError):
        return _json_response(start_response, "400 Bad Request", {"error": "Invalid request parameters."})
    except Exception:
        log.exception("Dashboard request failed for %s", path)
        return _json_response(start_response, "500 Internal Server Error", {"error": "Dashboard data could not be loaded."})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve the local vulnerability dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (defaults to localhost only).")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000).")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with make_server(args.host, args.port, application) as server:
        log.info("Dashboard listening at http://%s:%d", args.host, args.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("Dashboard stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
