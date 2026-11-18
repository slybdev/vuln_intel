"""Persistence and PostgreSQL queue operations for application scans."""
from __future__ import annotations

import hashlib
import json
import uuid

from vuln_intel.database import _connect, _ensure_schema


class IdempotencyConflict(ValueError):
    pass


def _row_dict(row, columns):
    return dict(zip(columns, row))


def enqueue_scan(application_id: str, commit_sha: str, ref: str, idempotency_key: str):
    run_id = str(uuid.uuid4())
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                INSERT INTO scan_runs (run_id, application_id, commit_sha, ref, idempotency_key, status)
                VALUES (%s, %s, %s, %s, %s, 'queued')
                ON CONFLICT (idempotency_key) DO NOTHING
                RETURNING run_id, application_id, commit_sha, ref, status, requested_at
                """,
                (run_id, application_id, commit_sha, ref, idempotency_key),
            )
            row = cur.fetchone()
            created = row is not None
            if row is None:
                cur.execute(
                    """
                    SELECT run_id, application_id, commit_sha, ref, status, requested_at
                    FROM scan_runs WHERE idempotency_key = %s
                    """,
                    (idempotency_key,),
                )
                row = cur.fetchone()
                if row is None or row[1:4] != (application_id, commit_sha, ref):
                    raise IdempotencyConflict("Idempotency key was already used for a different scan request.")
    return _row_dict(row, ("run_id", "application_id", "commit_sha", "ref", "status", "requested_at")), created


def claim_scan(max_attempts: int = 3):
    lease_token = uuid.uuid4().hex
    conn, Jsonb = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                UPDATE scan_runs
                SET status = 'failed', completed_at = now(), lease_until = NULL, lease_token = NULL,
                    error = coalesce(error, 'Worker lease expired after the maximum attempts.')
                WHERE status = 'running' AND lease_until < now() AND attempts >= %s
                RETURNING status, run_id, application_id, commit_sha, ref, requested_at, started_at, completed_at,
                          component_count, finding_count, unevaluated_count, error
                """,
                (max_attempts,),
            )
            failed_runs = cur.fetchall()
            from vuln_intel.inventory_integration import enqueue_scan_callback
            for failed in failed_runs:
                enqueue_scan_callback(
                    cur, Jsonb,
                    dict(zip(("status", "run_id", "application_id", "commit_sha", "ref", "requested_at", "started_at",
                              "completed_at", "component_count", "finding_count", "unevaluated_count", "error"),
                             failed)),
                    "scan.failed",
                    error=failed[-1],
                )
            cur.execute(
                """
                WITH candidate AS (
                    SELECT run_id
                    FROM scan_runs
                    WHERE attempts < %s
                      AND (
                        (status = 'queued' AND available_at <= now())
                        OR (status = 'running' AND lease_until < now())
                      )
                    ORDER BY requested_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE scan_runs AS run
                SET status = 'running',
                    started_at = coalesce(run.started_at, now()),
                    lease_until = now() + interval '2 hours',
                    lease_token = %s,
                    attempts = run.attempts + 1,
                    error = NULL
                FROM candidate
                WHERE run.run_id = candidate.run_id
                RETURNING run.run_id, run.application_id, run.commit_sha, run.ref, run.attempts, run.lease_token
                """,
                (max_attempts, lease_token),
            )
            row = cur.fetchone()
    return _row_dict(row, ("run_id", "application_id", "commit_sha", "ref", "attempts", "lease_token")) if row else None


def retry_or_fail_scan(run_id: str, lease_token: str, error: str, max_attempts: int = 3):
    conn, Jsonb = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                UPDATE scan_runs
                SET status = CASE WHEN attempts < %s THEN 'queued' ELSE 'failed' END,
                    available_at = now() + (least(60, power(2, attempts) * 10) * interval '1 second'),
                    lease_until = NULL,
                    lease_token = NULL,
                    completed_at = CASE WHEN attempts < %s THEN NULL ELSE now() END,
                    error = %s
                WHERE run_id = %s AND lease_token = %s AND status = 'running'
                RETURNING status, run_id, application_id, commit_sha, ref, requested_at, started_at, completed_at,
                          component_count, finding_count, unevaluated_count, error
                """,
                (max_attempts, max_attempts, error[:2000], run_id, lease_token),
            )
            failed = cur.fetchone()
            if failed and failed[0] == "failed":
                from vuln_intel.inventory_integration import enqueue_scan_callback
                enqueue_scan_callback(
                    cur, Jsonb,
                    dict(zip(("status", "run_id", "application_id", "commit_sha", "ref", "requested_at",
                              "started_at", "completed_at", "component_count", "finding_count",
                              "unevaluated_count", "error"), failed)),
                    "scan.failed",
                    error=failed[-1],
                )


def _finding_key(component_key: str, vulnerability_key: str) -> str:
    return hashlib.sha256(f"{component_key}\0{vulnerability_key}".encode("utf-8")).hexdigest()


def update_scan_target(run_id: str, lease_token: str, commit_sha: str, ref: str):
    conn, _ = _connect()
    with conn, conn.cursor() as cur:
        _ensure_schema(cur)
        cur.execute(
            """
            UPDATE scan_runs
            SET commit_sha = %s, ref = %s
            WHERE run_id = %s AND status = 'running' AND lease_token = %s
            """,
            (commit_sha, ref, run_id, lease_token),
        )
        if cur.rowcount != 1:
            raise RuntimeError("Scan lease expired before the repository target could be recorded.")


def save_scan_result(run_id: str, lease_token: str, application_id: str, ref: str, components: list[dict],
                     findings: list[dict], evaluations: list[dict], scanner_version: str, scanner_db_updated: str | None,
                     report_path: str, sbom_path: str, report_sha256: str, sbom_sha256: str,
                     inventory_name: str | None = None):
    conn, Jsonb = _connect()
    component_map = {component["component_key"]: component for component in components}
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT status, lease_token, commit_sha, requested_at, started_at
                FROM scan_runs WHERE run_id = %s FOR UPDATE
                """,
                (run_id,),
            )
            lease = cur.fetchone()
            if not lease or lease[:2] != ("running", lease_token):
                raise RuntimeError("Scan lease expired before results could be committed.")
            cur.execute("DELETE FROM scan_components WHERE run_id = %s", (run_id,))
            if components:
                cur.executemany(
                    """
                    INSERT INTO scan_components
                        (run_id, component_key, purl, ecosystem, release, package_name, version, target, properties)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (run_id, item["component_key"], item.get("purl"), item["ecosystem"], item.get("release"),
                         item["package_name"], item["version"], item.get("target", ""), Jsonb(item.get("properties") or {}))
                        for item in components
                    ],
                )
            persisted_findings = []
            callback_findings = []
            for finding in findings:
                component = component_map.get(finding["component_key"])
                if not component:
                    continue
                canonical_id = finding.get("canonical_id")
                vulnerability_id = finding["vulnerability_id"]
                vulnerability_key = canonical_id or vulnerability_id.upper()
                callback_findings.append({
                    "vulnerability_id": vulnerability_id,
                    "canonical_id": canonical_id,
                    "ecosystem": component["ecosystem"],
                    "package_name": component["package_name"],
                    "installed_version": component["version"],
                    "fixed_version": finding.get("fixed_version"),
                    "severity": finding.get("severity", "UNKNOWN"),
                    "sources": sorted(set(finding.get("sources") or [])),
                })
                persisted_findings.append((
                    run_id,
                    _finding_key(component["component_key"], vulnerability_key),
                    component["component_key"],
                    canonical_id,
                    vulnerability_id,
                    component["ecosystem"],
                    component.get("release"),
                    component["package_name"],
                    component.get("purl"),
                    component["version"],
                    finding.get("fixed_version"),
                    finding.get("severity", "UNKNOWN"),
                    Jsonb(sorted(set(finding.get("sources") or []))),
                    Jsonb(finding.get("evidence") or {}),
                ))
            if persisted_findings:
                cur.executemany(
                    """
                    INSERT INTO scan_findings
                        (run_id, finding_key, component_key, canonical_id, vulnerability_id, ecosystem, release,
                         package_name, purl, installed_version, fixed_version, severity, sources, evidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (run_id, finding_key) DO UPDATE SET
                        sources = EXCLUDED.sources,
                        evidence = EXCLUDED.evidence,
                        fixed_version = EXCLUDED.fixed_version,
                        severity = EXCLUDED.severity
                    """,
                    persisted_findings,
                )
                cur.executemany(
                    """
                    INSERT INTO application_findings
                        (application_id, ref, component_key, vulnerability_key, canonical_id, vulnerability_id,
                         ecosystem, release, package_name, purl, installed_version, fixed_version, severity,
                         status, last_scan_id, sources, evidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s)
                    ON CONFLICT (application_id, ref, component_key, vulnerability_key) DO UPDATE SET
                        canonical_id = EXCLUDED.canonical_id,
                        vulnerability_id = EXCLUDED.vulnerability_id,
                        ecosystem = EXCLUDED.ecosystem,
                        release = EXCLUDED.release,
                        package_name = EXCLUDED.package_name,
                        purl = EXCLUDED.purl,
                        installed_version = EXCLUDED.installed_version,
                        fixed_version = EXCLUDED.fixed_version,
                        severity = EXCLUDED.severity,
                        status = 'active',
                        last_seen = now(),
                        last_scan_id = EXCLUDED.last_scan_id,
                        sources = EXCLUDED.sources,
                        evidence = EXCLUDED.evidence
                    """,
                    [
                        (application_id, ref, row[2], row[4] if not row[3] else row[3], row[3], row[4], row[5], row[6],
                         row[7], row[8], row[9], row[10], row[11], run_id, row[12], row[13])
                        for row in persisted_findings
                    ],
                )
            if evaluations:
                cur.executemany(
                    """
                    INSERT INTO scan_match_evaluations
                        (run_id, component_key, canonical_id, status, reason, evidence)
                    VALUES (%s, %s, %s, 'unevaluated', %s, %s)
                    ON CONFLICT (run_id, component_key, canonical_id) DO UPDATE SET
                        reason = EXCLUDED.reason, evidence = EXCLUDED.evidence
                    """,
                    [
                        (run_id, item["component_key"], item["canonical_id"], item["reason"], Jsonb(item["evidence"]))
                        for item in evaluations
                    ],
                )
            cur.execute(
                """
                UPDATE application_findings AS current
                SET status = 'resolved', last_scan_id = %s
                WHERE current.application_id = %s
                  AND current.ref = %s
                  AND current.status = 'active'
                  AND current.last_scan_id <> %s
                  AND NOT EXISTS (
                    SELECT 1
                    FROM scan_findings AS finding
                    WHERE finding.run_id = %s
                      AND finding.component_key = current.component_key
                      AND coalesce(finding.canonical_id, upper(finding.vulnerability_id)) = current.vulnerability_key
                  )
                """,
                (run_id, application_id, ref, run_id, run_id),
            )
            cur.execute(
                """
                UPDATE scan_runs
                SET status = 'succeeded', completed_at = now(), lease_until = NULL, lease_token = NULL, error = NULL,
                    scanner_version = %s, scanner_db_updated = %s, report_path = %s, sbom_path = %s,
                    report_sha256 = %s, sbom_sha256 = %s, component_count = %s, finding_count = %s,
                    unevaluated_count = %s, inventory_name = %s
                WHERE run_id = %s AND status = 'running' AND lease_token = %s
                RETURNING completed_at
                """,
                (scanner_version, scanner_db_updated, report_path, sbom_path, report_sha256, sbom_sha256,
                 len(components), len(persisted_findings), len(evaluations), inventory_name, run_id, lease_token),
            )
            completed = cur.fetchone()
            if not completed:
                raise RuntimeError("Scan lease expired before results could be committed.")
            from vuln_intel.inventory_integration import enqueue_scan_callback
            enqueue_scan_callback(
                cur, Jsonb,
                {
                    "run_id": run_id,
                    "application_id": application_id,
                    "commit_sha": lease[2],
                    "ref": ref,
                    "status": "succeeded",
                    "requested_at": lease[3],
                    "started_at": lease[4],
                    "completed_at": completed[0],
                    "component_count": len(components),
                    "finding_count": len(persisted_findings),
                    "unevaluated_count": len(evaluations),
                },
                "scan.completed",
                findings=callback_findings,
            )


def get_candidate_vulnerabilities(ecosystem: str, package_name: str):
    conn, _ = _connect()
    containment = json.dumps([{"ecosystem": ecosystem, "package": package_name}])
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT canonical_id, payload
                FROM vulnerabilities
                WHERE payload->'affected' @> %s::jsonb
                """,
                (containment,),
            )
            return cur.fetchall()


def resolve_identifier(identifier: str):
    normalized = identifier.upper() if identifier.upper().startswith("CVE-") else identifier
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT canonical_id
                FROM vulnerability_ids
                WHERE identifier = %s
                """,
                (normalized,),
            )
            row = cur.fetchone()
    return row[0] if row else None


def list_scan_runs(application_id: str = "", limit: int = 100):
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            if application_id:
                cur.execute(
                    """
                    SELECT run_id, application_id, commit_sha, ref, status, requested_at, started_at, completed_at,
                           component_count, finding_count, unevaluated_count, scanner_version, error
                    FROM scan_runs WHERE application_id = %s
                    ORDER BY requested_at DESC LIMIT %s
                    """,
                    (application_id, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT run_id, application_id, commit_sha, ref, status, requested_at, started_at, completed_at,
                           component_count, finding_count, unevaluated_count, scanner_version, error
                    FROM scan_runs ORDER BY requested_at DESC LIMIT %s
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
    columns = ("run_id", "application_id", "commit_sha", "ref", "status", "requested_at", "started_at",
               "completed_at", "component_count", "finding_count", "unevaluated_count", "scanner_version", "error")
    return [_row_dict(row, columns) for row in rows]


def get_scan_run(run_id: str):
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT run_id, application_id, commit_sha, ref, status, requested_at, started_at, completed_at,
                       component_count, finding_count, unevaluated_count, scanner_version, scanner_db_updated, report_sha256,
                       sbom_sha256, inventory_name, error
                FROM scan_runs WHERE run_id = %s
                """,
                (run_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            run = _row_dict(row, ("run_id", "application_id", "commit_sha", "ref", "status", "requested_at",
                                  "started_at", "completed_at", "component_count", "finding_count",
                                  "unevaluated_count", "scanner_version", "scanner_db_updated", "report_sha256", "sbom_sha256",
                                  "inventory_name", "error"))
            cur.execute(
                """
                SELECT canonical_id, vulnerability_id, ecosystem, release, package_name, purl, installed_version,
                       fixed_version, severity, sources, evidence
                FROM scan_findings WHERE run_id = %s
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                                       WHEN 'LOW' THEN 3 ELSE 4 END, vulnerability_id, package_name
                """,
                (run_id,),
            )
            finding_rows = cur.fetchall()
            cur.execute(
                """
                SELECT evaluation.canonical_id, component.ecosystem, component.release, component.package_name,
                       component.purl, evaluation.reason, evaluation.evidence
                FROM scan_match_evaluations AS evaluation
                JOIN scan_components AS component
                  ON component.run_id = evaluation.run_id
                 AND component.component_key = evaluation.component_key
                WHERE evaluation.run_id = %s
                ORDER BY evaluation.canonical_id, component.package_name
                """,
                (run_id,),
            )
            evaluation_rows = cur.fetchall()
    columns = ("canonical_id", "vulnerability_id", "ecosystem", "release", "package_name", "purl",
               "installed_version", "fixed_version", "severity", "sources", "evidence")
    run["findings"] = [_row_dict(item, columns) for item in finding_rows]
    run["unevaluated"] = [
        _row_dict(item, ("canonical_id", "ecosystem", "release", "package_name", "purl", "reason", "evidence"))
        for item in evaluation_rows
    ]
    return run


def list_application_findings(application_id: str, ref: str = "", status: str = "active"):
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT ref, canonical_id, vulnerability_id, ecosystem, release, package_name, purl,
                       installed_version, fixed_version, severity, status, first_seen, last_seen, sources
                FROM application_findings
                WHERE application_id = %s
                  AND (%s = '' OR ref = %s)
                  AND (%s = '' OR status = %s)
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                                       WHEN 'LOW' THEN 3 ELSE 4 END, vulnerability_id, package_name
                """,
                (application_id, ref, ref, status, status),
            )
            rows = cur.fetchall()
    columns = ("ref", "canonical_id", "vulnerability_id", "ecosystem", "release", "package_name", "purl",
               "installed_version", "fixed_version", "severity", "status", "first_seen", "last_seen", "sources")
    return [_row_dict(row, columns) for row in rows]
