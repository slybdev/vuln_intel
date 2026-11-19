"""Local web dashboard and loopback-only repository settings API."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import re
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote
from wsgiref.simple_server import make_server

from vuln_intel import (
    asset_store,
    config,
    dashboard_data,
    event_store,
    feed_schedule,
    inventory_integration,
    repository_connections,
    scan_service,
    scan_store,
)

log = logging.getLogger(__name__)
FRONTEND_DIR = Path(os.getenv("VULN_FRONTEND_DIR", Path(__file__).resolve().parents[1] / "dist"))
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
    if path == "/api/v1/inventory/repositories":
        if method != "POST":
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        if not config.INVENTORY_API_TOKEN:
            return _json_response(
                start_response, "503 Service Unavailable",
                {"error": "External inventory API authentication is not configured."},
            )
        supplied = environ.get("HTTP_AUTHORIZATION", "")
        token = supplied[7:] if supplied.startswith("Bearer ") else ""
        if not inventory_integration.inventory_token_is_valid(token):
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid bearer authentication is required."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
        try:
            registration = inventory_integration.register_repository(payload)
            scan, scan_created = scan_service.request_inventory_initial_scan(
                registration["repository"]["application_id"],
                payload["external_inventory_id"],
            )
        except inventory_integration.IntegrationConflict as exc:
            return _json_response(start_response, "409 Conflict", {"error": str(exc)})
        except repository_connections.RepositoryEncryptionError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except RuntimeError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except Exception:
            log.exception("Could not register external inventory repository.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Repository integration could not be registered."})
        return _json_response(start_response, "202 Accepted" if scan_created else "200 OK", {
            "repository": registration["repository"],
            "initial_scan": scan,
            "pipeline": registration["pipeline"],
            "callback": registration["callback"],
        })
    credential_prefix = "/api/v1/inventory/repositories/"
    credential_suffix = "/credential"
    if path.startswith(credential_prefix) and path.endswith(credential_suffix):
        if method != "POST":
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        if not config.INVENTORY_API_TOKEN:
            return _json_response(
                start_response, "503 Service Unavailable",
                {"error": "External inventory API authentication is not configured."},
            )
        supplied = environ.get("HTTP_AUTHORIZATION", "")
        token = supplied[7:] if supplied.startswith("Bearer ") else ""
        if not inventory_integration.inventory_token_is_valid(token):
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid bearer authentication is required."})
        application_id = unquote(path[len(credential_prefix):-len(credential_suffix)].strip("/"))
        try:
            credential = inventory_integration.rotate_pipeline_credential(application_id)
        except repository_connections.RepositoryEncryptionError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except RuntimeError as exc:
            return _json_response(start_response, "503 Service Unavailable", {"error": str(exc)})
        except Exception:
            log.exception("Could not rotate pipeline credential for %s.", application_id)
            return _json_response(start_response, "500 Internal Server Error", {"error": "Pipeline credential could not be rotated."})
        if credential is None:
            return _json_response(start_response, "404 Not Found", {"error": "Repository integration was not found."})
        return _json_response(start_response, "200 OK", {"pipeline": credential})
    pipeline_prefix = "/api/v1/inventory/repositories/"
    pipeline_suffix = "/scans"
    if path.startswith(pipeline_prefix) and path.endswith(pipeline_suffix):
        if method != "POST":
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        application_id = unquote(path[len(pipeline_prefix):-len(pipeline_suffix)].strip("/"))
        supplied = environ.get("HTTP_AUTHORIZATION", "")
        token = supplied[7:] if supplied.startswith("Bearer ") else ""
        try:
            authorized = inventory_integration.authenticate_pipeline(application_id, token)
        except Exception:
            log.exception("Could not authenticate inventory pipeline scan request.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Pipeline authentication could not be checked."})
        if not authorized:
            return _json_response(start_response, "401 Unauthorized", {"error": "Valid application bearer authentication is required."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
        request_payload = {
            "application_id": application_id,
            "commit_sha": payload.get("commit_sha"),
            "ref": payload.get("ref"),
            "event_id": payload.get("event_id"),
        }
        try:
            scan, created = scan_service.request_scan(request_payload)
        except scan_store.IdempotencyConflict as exc:
            return _json_response(start_response, "409 Conflict", {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not queue inventory pipeline scan for %s.", application_id)
            return _json_response(start_response, "500 Internal Server Error", {"error": "Scan could not be queued."})
        return _json_response(start_response, "202 Accepted" if created else "200 OK", {
            "scan": scan,
            "created": created,
        })
    if path == "/api/feed-schedule":
        if method not in {"GET", "PUT"}:
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        if method == "GET":
            try:
                return _json_response(start_response, "200 OK", {
                    "schedule": feed_schedule.get_schedule(),
                })
            except Exception:
                log.exception("Could not load the external feed update schedule.")
                return _json_response(start_response, "500 Internal Server Error", {"error": "Feed schedule could not be loaded."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "Request body must be a JSON object."})
        try:
            schedule = feed_schedule.save_schedule(
                payload.get("enabled"),
                payload.get("time"),
            )
        except ValueError as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not save the external feed update schedule.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Feed schedule could not be saved."})
        return _json_response(start_response, "200 OK", {"schedule": schedule})
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
            details = repository_connections.github_application_from_url(payload.get("repository_url"))
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        try:
            connection = repository_connections.save_repository_connection(
                details["application_id"], details["repository_url"], details["name"]
            )
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not save GitHub repository from scan request.")
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
    if path == "/api/security-events/summary":
        if method != "GET":
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        try:
            return _json_response(start_response, "200 OK", event_store.get_event_summary())
        except Exception:
            log.exception("Could not load the security event summary.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Security event summary could not be loaded."})
    if path == "/api/security-events":
        if method != "GET":
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        query = params.get("q", [""])[0].strip()
        severity = params.get("severity", [""])[0].upper()
        category = params.get("category", [""])[0]
        if len(query) > 200:
            return _json_response(start_response, "400 Bad Request", {"error": "Search query must be at most 200 characters."})
        if severity and severity not in event_store.EVENT_SEVERITIES:
            return _json_response(start_response, "400 Bad Request", {"error": "Invalid event severity."})
        if category and category not in event_store.EVENT_CATEGORIES:
            return _json_response(start_response, "400 Bad Request", {"error": "Invalid event category."})
        try:
            page = int(params.get("page", ["1"])[0])
            page_size = min(100, max(1, int(params.get("page_size", ["25"])[0])))
        except ValueError:
            return _json_response(start_response, "400 Bad Request", {"error": "Page and page_size must be integers."})
        if page < 1 or page > 1000000:
            return _json_response(start_response, "400 Bad Request", {"error": "Page must be between 1 and 1000000."})
        try:
            return _json_response(
                start_response,
                "200 OK",
                event_store.list_events(query, severity, category, page, page_size),
            )
        except Exception:
            log.exception("Could not load security events.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Security events could not be loaded."})
    if path == "/api/assets/summary":
        if method != "GET":
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        try:
            return _json_response(start_response, "200 OK", asset_store.get_asset_summary())
        except Exception:
            log.exception("Could not load asset inventory summary.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Asset summary could not be loaded."})
    if path == "/api/assets":
        if method not in {"GET", "POST"}:
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        if method == "GET":
            params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
            query = params.get("q", [""])[0].strip()
            asset_type = params.get("type", [""])[0]
            status = params.get("status", [""])[0]
            if len(query) > 200:
                return _json_response(start_response, "400 Bad Request", {"error": "Search query must be at most 200 characters."})
            if asset_type and asset_type not in asset_store.ASSET_TYPES:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid asset type."})
            if status and status not in asset_store.ASSET_STATUSES:
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid asset status."})
            try:
                page = int(params.get("page", ["1"])[0])
                page_size = min(100, max(1, int(params.get("page_size", ["25"])[0])))
            except ValueError:
                return _json_response(start_response, "400 Bad Request", {"error": "Page and page_size must be integers."})
            if page < 1 or page > 1000000:
                return _json_response(start_response, "400 Bad Request", {"error": "Page must be between 1 and 1000000."})
            try:
                return _json_response(
                    start_response,
                    "200 OK",
                    asset_store.list_assets(query, asset_type, status, page, page_size),
                )
            except Exception:
                log.exception("Could not load the asset inventory.")
                return _json_response(start_response, "500 Internal Server Error", {"error": "Asset inventory could not be loaded."})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        try:
            asset = asset_store.create_asset(payload)
        except asset_store.AssetConflict as exc:
            return _json_response(start_response, "409 Conflict", {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not create an inventory asset.")
            return _json_response(start_response, "500 Internal Server Error", {"error": "Asset could not be created."})
        return _json_response(start_response, "201 Created", {"asset": asset})
    if path.startswith("/api/assets/"):
        if method not in {"GET", "PATCH", "DELETE"}:
            return _json_response(start_response, "405 Method Not Allowed", {"error": "Method not allowed."})
        denied = _local_settings_access_failure(environ, start_response)
        if denied:
            return denied
        raw_id = unquote(path[len("/api/assets/"):])
        try:
            asset_id = str(uuid.UUID(raw_id))
        except (ValueError, AttributeError):
            return _json_response(start_response, "400 Bad Request", {"error": "Invalid asset ID."})
        if method == "GET":
            try:
                asset = asset_store.get_asset(asset_id)
            except Exception:
                log.exception("Could not load asset %s.", asset_id)
                return _json_response(start_response, "500 Internal Server Error", {"error": "Asset could not be loaded."})
            if asset is None:
                return _json_response(start_response, "404 Not Found", {"error": "Asset not found."})
            return _json_response(start_response, "200 OK", {"asset": asset})
        if method == "DELETE":
            try:
                deleted = asset_store.delete_asset(asset_id)
            except Exception:
                log.exception("Could not delete asset %s.", asset_id)
                return _json_response(start_response, "500 Internal Server Error", {"error": "Asset could not be deleted."})
            if not deleted:
                return _json_response(start_response, "404 Not Found", {"error": "Asset not found."})
            return _json_response(start_response, "200 OK", {"deleted": True})
        payload, error = _read_json_request(environ, start_response)
        if error:
            return error
        try:
            asset = asset_store.update_asset(asset_id, payload)
        except asset_store.AssetConflict as exc:
            return _json_response(start_response, "409 Conflict", {"error": str(exc)})
        except (TypeError, ValueError) as exc:
            return _json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except Exception:
            log.exception("Could not update asset %s.", asset_id)
            return _json_response(start_response, "500 Internal Server Error", {"error": "Asset could not be updated."})
        if asset is None:
            return _json_response(start_response, "404 Not Found", {"error": "Asset not found."})
        return _json_response(start_response, "200 OK", {"asset": asset})
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
        if path.startswith("/api/applications/") and path.endswith("/finding-details"):
            raw_id = unquote(path[len("/api/applications/"):-len("/finding-details")].strip("/"))
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", raw_id):
                return _json_response(start_response, "400 Bad Request", {"error": "Invalid application_id."})
            params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
            finding_fields = {
                "ref": (255, params.get("ref", [""])[0]),
                "vulnerability_id": (160, params.get("vulnerability_id", [""])[0]),
                "package_name": (512, params.get("package_name", [""])[0]),
                "installed_version": (512, params.get("installed_version", [""])[0]),
            }
            if any(
                not value or len(value) > max_length or any(ord(char) < 32 for char in value)
                for max_length, value in finding_fields.values()
            ):
                return _json_response(start_response, "400 Bad Request", {
                    "error": "A valid ref, vulnerability_id, package_name, and installed_version are required.",
                })
            finding = scan_store.get_application_finding_details(
                raw_id,
                finding_fields["ref"][1],
                finding_fields["vulnerability_id"][1],
                finding_fields["package_name"][1],
                finding_fields["installed_version"][1],
            )
            if finding is None:
                return _json_response(start_response, "404 Not Found", {"error": "Application finding not found."})
            return _json_response(start_response, "200 OK", finding)
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
        candidate = (FRONTEND_DIR / relative).resolve()
        if FRONTEND_DIR.resolve() not in candidate.parents or not candidate.is_file():
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
    parser = argparse.ArgumentParser(description="Serve the Tactical Ops UI and vulnerability API.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (defaults to localhost only).")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000).")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    feed_schedule.start_worker()
    try:
        with make_server(args.host, args.port, application) as server:
            log.info("Tactical Ops application listening at http://%s:%d", args.host, args.port)
            server.serve_forever()
    except KeyboardInterrupt:
        log.info("Dashboard stopped.")
    finally:
        feed_schedule.stop_worker()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
