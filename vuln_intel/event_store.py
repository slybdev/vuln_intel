"""Persistence and queries for platform-generated security audit events."""
from __future__ import annotations

from threading import Lock

from vuln_intel.database import _connect, _ensure_schema

EVENT_CATEGORIES = {
    "asset",
    "repository",
    "scan",
    "finding",
    "feed",
    "settings",
    "system",
}
EVENT_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
EVENT_OUTCOMES = {
    "info",
    "queued",
    "running",
    "succeeded",
    "failed",
    "detected",
    "resolved",
    "updated",
    "deleted",
    "partial",
}
_backfill_lock = Lock()
_backfill_complete = False


def insert_event(
    cursor,
    jsonb,
    *,
    severity,
    category,
    event_type,
    source,
    message,
    target_type="",
    target_id="",
    outcome="info",
    actor="system",
    details=None,
    event_key=None,
    occurred_at=None,
):
    cursor.execute(
        """
        INSERT INTO security_events
            (event_key, occurred_at, severity, category, event_type, source, message,
             target_type, target_id, outcome, actor, details)
        VALUES (%s, coalesce(%s, now()), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (event_key) DO NOTHING
        """,
        (
            event_key,
            occurred_at,
            severity,
            category,
            event_type,
            source,
            message,
            target_type,
            target_id,
            outcome,
            actor,
            jsonb(details or {}),
        ),
    )


def record_event(**event):
    """Persist an event that is not part of another database transaction."""
    conn, Jsonb = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            insert_event(cur, Jsonb, **event)


def backfill_existing_events():
    """Create truthful first-run history from persisted records, idempotently."""
    global _backfill_complete
    if _backfill_complete:
        return
    with _backfill_lock:
        if _backfill_complete:
            return
        conn, Jsonb = _connect()
        with conn:
            with conn.cursor() as cur:
                _ensure_schema(cur)
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:repository:' || application_id || ':created',
                        created_at, 'INFO', 'repository', 'repository.connected',
                        'Repository inventory', 'Repository connected: ' || name,
                        'repository', application_id, 'succeeded', 'history',
                        jsonb_build_object('repository_url', repository_url)
                    FROM repository_connections
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:finding:' ||
                            md5(jsonb_build_array(application_id, ref, component_key, vulnerability_key)::text) ||
                            ':detected',
                        first_seen, severity, 'finding', 'finding.detected',
                        'Vulnerability scan history',
                        'Finding detected: ' || vulnerability_id || ' in ' || package_name,
                        'repository', application_id, 'detected', 'history',
                        jsonb_build_object(
                            'ref', ref,
                            'package_name', package_name,
                            'installed_version', installed_version,
                            'vulnerability_id', vulnerability_id,
                            'fixed_version', fixed_version
                        )
                    FROM application_findings
                    WHERE status = 'active'
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:finding:' ||
                            md5(jsonb_build_array(finding.application_id, finding.ref,
                                                 finding.component_key, finding.vulnerability_key)::text) ||
                            ':resolved',
                        coalesce(resolver.completed_at, finding.last_seen),
                        'INFO', 'finding', 'finding.resolved',
                        'Vulnerability scan history',
                        'Finding resolved: ' || finding.vulnerability_id || ' in ' || finding.package_name,
                        'repository', finding.application_id, 'resolved', 'history',
                        jsonb_build_object(
                            'ref', finding.ref,
                            'package_name', finding.package_name,
                            'installed_version', finding.installed_version,
                            'vulnerability_id', finding.vulnerability_id,
                            'fixed_version', finding.fixed_version,
                            'severity', finding.severity
                        )
                    FROM application_findings AS finding
                    LEFT JOIN scan_runs AS resolver
                      ON resolver.run_id = finding.last_scan_id
                    WHERE finding.status = 'resolved'
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:asset:' || asset_id || ':created',
                        created_at, 'INFO', 'asset', 'asset.registered',
                        'Asset inventory', 'Asset registered: ' || name,
                        'asset', asset_id, 'succeeded', 'history',
                        jsonb_build_object('asset_type', asset_type, 'identifier', identifier)
                    FROM assets
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:scan:' || run_id || ':queued',
                        requested_at, 'INFO', 'scan', 'scan.queued',
                        'Scan queue', 'Scan queued for ' || coalesce(repository.name, run.application_id),
                        'repository', run.application_id, 'queued', 'history',
                        jsonb_build_object('run_id', run.run_id, 'ref', run.ref, 'commit_sha', run.commit_sha)
                    FROM scan_runs AS run
                    LEFT JOIN repository_connections AS repository
                      ON repository.application_id = run.application_id
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:scan:' || run_id || ':started',
                        started_at, 'INFO', 'scan', 'scan.started',
                        'Scan worker', 'Scan started for ' || coalesce(repository.name, run.application_id),
                        'repository', run.application_id, 'running', 'history',
                        jsonb_build_object('run_id', run.run_id, 'attempts', run.attempts)
                    FROM scan_runs AS run
                    LEFT JOIN repository_connections AS repository
                      ON repository.application_id = run.application_id
                    WHERE started_at IS NOT NULL
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, occurred_at, severity, category, event_type, source, message,
                         target_type, target_id, outcome, actor, details)
                    SELECT
                        'history:scan:' || run.run_id || ':finished',
                        run.completed_at,
                        CASE WHEN run.status = 'failed' THEN 'HIGH' ELSE 'INFO' END,
                        'scan',
                        CASE WHEN run.status = 'failed' THEN 'scan.failed' ELSE 'scan.completed' END,
                        'Scan worker',
                        CASE WHEN run.status = 'failed'
                             THEN 'Scan failed for ' || coalesce(repository.name, run.application_id)
                             ELSE 'Scan completed for ' || coalesce(repository.name, run.application_id)
                        END,
                        'repository', run.application_id, run.status, 'history',
                        jsonb_build_object(
                            'run_id', run.run_id,
                            'component_count', run.component_count,
                            'finding_count', run.finding_count,
                            'unevaluated_count', run.unevaluated_count
                        )
                    FROM scan_runs AS run
                    LEFT JOIN repository_connections AS repository
                      ON repository.application_id = run.application_id
                    WHERE run.completed_at IS NOT NULL AND run.status IN ('succeeded', 'failed')
                    ON CONFLICT (event_key) DO NOTHING
                    """
                )
        _backfill_complete = True


def list_events(query="", severity="", category="", page=1, page_size=25):
    backfill_existing_events()
    conditions, params = [], []
    if query:
        pattern = f"%{query}%"
        conditions.append(
            "(message ILIKE %s OR source ILIKE %s OR event_type ILIKE %s "
            "OR target_id ILIKE %s OR actor ILIKE %s)"
        )
        params.extend([pattern] * 5)
    if severity:
        conditions.append("severity = %s")
        params.append(severity)
    if category:
        conditions.append("category = %s")
        params.append(category)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(f"SELECT count(*) FROM security_events {where}", tuple(params))
            total = cur.fetchone()[0]
            cur.execute(
                f"""
                SELECT event_id, occurred_at, severity, category, event_type, source, message,
                       target_type, target_id, outcome, actor, details
                FROM security_events
                {where}
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT %s OFFSET %s
                """,
                tuple(params + [page_size, (page - 1) * page_size]),
            )
            columns = (
                "event_id",
                "occurred_at",
                "severity",
                "category",
                "event_type",
                "source",
                "message",
                "target_type",
                "target_id",
                "outcome",
                "actor",
                "details",
            )
            items = [dict(zip(columns, row)) for row in cur.fetchall()]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def get_event_summary():
    backfill_existing_events()
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT count(*),
                       count(*) FILTER (WHERE occurred_at >= now() - interval '24 hours'),
                       count(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH')),
                       count(*) FILTER (WHERE outcome = 'failed')
                FROM security_events
                """
            )
            total, last_24_hours, high_severity, failed = cur.fetchone()
    return {
        "total": total,
        "last_24_hours": last_24_hours,
        "high_severity": high_severity,
        "failed": failed,
    }
