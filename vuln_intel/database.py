"""PostgreSQL persistence for standardized vulnerabilities and source contributions."""
from __future__ import annotations

from vuln_intel import config
from vuln_intel.utils import read_json, stable_hash

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        canonical_id TEXT PRIMARY KEY,
        payload JSONB NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerability_ids (
        identifier TEXT PRIMARY KEY,
        canonical_id TEXT NOT NULL REFERENCES vulnerabilities(canonical_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS vulnerability_ids_canonical_id_idx
    ON vulnerability_ids(canonical_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS vulnerabilities_affected_packages_gin_idx
    ON vulnerabilities USING GIN ((payload->'affected') jsonb_path_ops)
    """,
    """
    CREATE TABLE IF NOT EXISTS source_contributions (
        contribution_key TEXT PRIMARY KEY,
        payload JSONB NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS pipeline_metadata (
        metadata_key TEXT PRIMARY KEY,
        payload JSONB NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS processed_runs (
        run_id TEXT PRIMARY KEY,
        processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS repository_connections (
        application_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        repository_url TEXT NOT NULL,
        encrypted_access_token BYTEA,
        encrypted_username BYTEA,
        encrypted_password BYTEA,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inventory_integrations (
        external_inventory_id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL UNIQUE,
        callback_url TEXT NOT NULL,
        encrypted_pipeline_token BYTEA NOT NULL,
        pipeline_token_hash TEXT NOT NULL,
        encrypted_callback_secret BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    ALTER TABLE repository_connections ADD COLUMN IF NOT EXISTS encrypted_username BYTEA
    """,
    """
    ALTER TABLE repository_connections ADD COLUMN IF NOT EXISTS encrypted_password BYTEA
    """,
    """
    CREATE TABLE IF NOT EXISTS git_provider_credentials (
        provider TEXT PRIMARY KEY CHECK (provider IN ('github', 'gitlab')),
        encrypted_username BYTEA NOT NULL,
        encrypted_password BYTEA NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        run_id TEXT PRIMARY KEY,
        application_id TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        ref TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
        requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        started_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        lease_until TIMESTAMPTZ,
        attempts INTEGER NOT NULL DEFAULT 0,
        scanner_version TEXT,
        scanner_db_updated TEXT,
        report_path TEXT,
        sbom_path TEXT,
        report_sha256 TEXT,
        sbom_sha256 TEXT,
        component_count INTEGER NOT NULL DEFAULT 0,
        finding_count INTEGER NOT NULL DEFAULT 0,
        unevaluated_count INTEGER NOT NULL DEFAULT 0,
        inventory_name TEXT,
        error TEXT
    )
    """,
    """
    ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS lease_token TEXT
    """,
    """
    ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS unevaluated_count INTEGER NOT NULL DEFAULT 0
    """,
    """
    CREATE INDEX IF NOT EXISTS scan_runs_queue_idx
    ON scan_runs(status, available_at, requested_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS scan_runs_application_idx
    ON scan_runs(application_id, requested_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS inventory_callback_outbox (
        event_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL UNIQUE REFERENCES scan_runs(run_id) ON DELETE CASCADE,
        application_id TEXT NOT NULL,
        callback_url TEXT NOT NULL,
        encrypted_callback_secret BYTEA NOT NULL,
        payload JSONB NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        delivered_at TIMESTAMPTZ,
        last_error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS inventory_callback_outbox_pending_idx
    ON inventory_callback_outbox(available_at, created_at) WHERE delivered_at IS NULL
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_components (
        run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
        component_key TEXT NOT NULL,
        purl TEXT,
        ecosystem TEXT NOT NULL,
        release TEXT,
        package_name TEXT NOT NULL,
        version TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        properties JSONB NOT NULL DEFAULT '{}'::jsonb,
        PRIMARY KEY (run_id, component_key)
    )
    """,
    """
    ALTER TABLE scan_components ADD COLUMN IF NOT EXISTS release TEXT
    """,
    """
    CREATE INDEX IF NOT EXISTS scan_components_package_idx
    ON scan_components(ecosystem, package_name, version)
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_findings (
        run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
        finding_key TEXT NOT NULL,
        component_key TEXT NOT NULL,
        canonical_id TEXT,
        vulnerability_id TEXT NOT NULL,
        ecosystem TEXT NOT NULL,
        release TEXT,
        package_name TEXT NOT NULL,
        purl TEXT,
        installed_version TEXT NOT NULL,
        fixed_version TEXT,
        severity TEXT NOT NULL DEFAULT 'UNKNOWN',
        sources JSONB NOT NULL,
        evidence JSONB NOT NULL,
        PRIMARY KEY (run_id, finding_key),
        FOREIGN KEY (run_id, component_key)
            REFERENCES scan_components(run_id, component_key) ON DELETE CASCADE
    )
    """,
    """
    ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS release TEXT
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_match_evaluations (
        run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
        component_key TEXT NOT NULL,
        canonical_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('unevaluated')),
        reason TEXT NOT NULL,
        evidence JSONB NOT NULL,
        PRIMARY KEY (run_id, component_key, canonical_id),
        FOREIGN KEY (run_id, component_key)
            REFERENCES scan_components(run_id, component_key) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS scan_findings_vulnerability_idx
    ON scan_findings(canonical_id, vulnerability_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS application_findings (
        application_id TEXT NOT NULL,
        ref TEXT NOT NULL,
        component_key TEXT NOT NULL,
        vulnerability_key TEXT NOT NULL,
        canonical_id TEXT,
        vulnerability_id TEXT NOT NULL,
        ecosystem TEXT NOT NULL,
        release TEXT,
        package_name TEXT NOT NULL,
        purl TEXT,
        installed_version TEXT NOT NULL,
        fixed_version TEXT,
        severity TEXT NOT NULL DEFAULT 'UNKNOWN',
        status TEXT NOT NULL CHECK (status IN ('active', 'resolved')),
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_scan_id TEXT NOT NULL REFERENCES scan_runs(run_id),
        sources JSONB NOT NULL,
        evidence JSONB NOT NULL,
        PRIMARY KEY (application_id, ref, component_key, vulnerability_key)
    )
    """,
    """
    ALTER TABLE application_findings ADD COLUMN IF NOT EXISTS release TEXT
    """,
    """
    CREATE INDEX IF NOT EXISTS application_findings_current_idx
    ON application_findings(application_id, ref, status, severity)
    """,
    """
    CREATE TABLE IF NOT EXISTS assets (
        asset_id TEXT PRIMARY KEY,
        asset_type TEXT NOT NULL CHECK (asset_type IN (
            'endpoint', 'server', 'network_device', 'operating_system',
            'third_party_application', 'cloud_resource'
        )),
        name TEXT NOT NULL,
        identifier TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active', 'maintenance', 'retired', 'unknown')),
        environment TEXT NOT NULL DEFAULT '',
        owner TEXT NOT NULL DEFAULT '',
        location TEXT NOT NULL DEFAULT '',
        vendor TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        operating_system TEXT NOT NULL DEFAULT '',
        version TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL DEFAULT '',
        mac_address TEXT NOT NULL DEFAULT '',
        criticality TEXT NOT NULL CHECK (criticality IN ('critical', 'high', 'medium', 'low', 'unknown')),
        notes TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS assets_type_identifier_unique_idx
    ON assets(asset_type, lower(identifier))
    """,
    """
    CREATE INDEX IF NOT EXISTS assets_inventory_order_idx
    ON assets(updated_at DESC, asset_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS security_events (
        event_id BIGSERIAL PRIMARY KEY,
        event_key TEXT UNIQUE,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
        category TEXT NOT NULL CHECK (category IN (
            'asset', 'repository', 'scan', 'finding', 'feed', 'settings', 'system'
        )),
        event_type TEXT NOT NULL,
        source TEXT NOT NULL,
        message TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT '',
        target_id TEXT NOT NULL DEFAULT '',
        outcome TEXT NOT NULL CHECK (outcome IN (
            'info', 'queued', 'running', 'succeeded', 'failed', 'detected',
            'resolved', 'updated', 'deleted', 'partial'
        )),
        actor TEXT NOT NULL DEFAULT 'system',
        details JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS feed_update_schedule (
        schedule_id SMALLINT PRIMARY KEY CHECK (schedule_id = 1),
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        run_time TIME NOT NULL,
        next_run_at TIMESTAMPTZ,
        last_run_at TIMESTAMPTZ,
        last_run_status TEXT CHECK (last_run_status IN ('running', 'succeeded', 'partial', 'failed')),
        last_run_error TEXT,
        last_run_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS security_events_occurred_idx
    ON security_events(occurred_at DESC, event_id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS security_events_category_idx
    ON security_events(category, occurred_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS security_events_severity_idx
    ON security_events(severity, occurred_at DESC)
    """,
)


def _connect():
    if not config.DATABASE_URL:
        raise RuntimeError("VULN_DATABASE_URL is not configured.")
    try:
        import psycopg
        from psycopg.types.json import Jsonb
    except ImportError as exc:
        raise RuntimeError("PostgreSQL storage requires psycopg; install the project requirements.") from exc
    return psycopg.connect(config.DATABASE_URL), Jsonb


def _ensure_schema(cursor):
    for statement in _SCHEMA:
        cursor.execute(statement)


def _baseline(vulnerabilities, contributions):
    return {
        "vulnerabilities": {key: stable_hash(value) for key, value in vulnerabilities.items()},
        "contributions": {key: stable_hash(value) for key, value in contributions.items()},
        "identifiers": {
            identifier: key
            for key, value in vulnerabilities.items()
            for identifier in value["ids"]
        },
    }


def _migrate_legacy_database():
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute("SELECT EXISTS (SELECT 1 FROM vulnerabilities)")
            if cur.fetchone()[0]:
                return

    legacy_db = read_json(config.DB_PATH, {"meta": {}, "vulnerabilities": {}})
    if not legacy_db.get("vulnerabilities"):
        return
    contributions = read_json(config.CONTRIB_PATH, {})
    if not contributions:
        raise RuntimeError(
            "A legacy JSON vulnerability database exists but its contribution file is missing or empty; "
            "refusing to migrate records without source provenance."
        )
    state = read_json(config.STATE_PATH, {"processed_runs": []})
    save_snapshot(legacy_db, contributions, None, state.get("processed_runs", []))


def load_existing_cves():
    _migrate_legacy_database()
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute("SELECT identifier FROM vulnerability_ids WHERE identifier ~* '^CVE-[0-9]{4}-[0-9]{4,}$'")
            return {row[0] for row in cur.fetchall()}


def load_snapshot():
    _migrate_legacy_database()
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute("SELECT canonical_id, payload FROM vulnerabilities")
            vulnerabilities = {canonical_id: payload for canonical_id, payload in cur.fetchall()}
            cur.execute("SELECT contribution_key, payload FROM source_contributions")
            contributions = {key: payload for key, payload in cur.fetchall()}
            cur.execute("SELECT payload FROM pipeline_metadata WHERE metadata_key = 'database'")
            row = cur.fetchone()
            meta = row[0] if row else {}
            cur.execute("SELECT run_id FROM processed_runs")
            processed_runs = {row[0] for row in cur.fetchall()}
    return ({"meta": meta, "vulnerabilities": vulnerabilities}, contributions, processed_runs,
            _baseline(vulnerabilities, contributions))


def save_snapshot(db, contributions, run_id=None, processed_runs=(), baseline=None, audit_event=None):
    conn, Jsonb = _connect()
    current = db["vulnerabilities"]
    baseline = baseline or {"vulnerabilities": {}, "contributions": {}, "identifiers": {}}
    changed_vulnerabilities = [
        (key, value) for key, value in current.items()
        if baseline["vulnerabilities"].get(key) != stable_hash(value)
    ]
    removed_vulnerabilities = set(baseline["vulnerabilities"]) - set(current)
    identifiers = {
        identifier: key
        for key, value in current.items()
        for identifier in value["ids"]
    }
    changed_identifiers = [
        (identifier, key) for identifier, key in identifiers.items()
        if baseline["identifiers"].get(identifier) != key
    ]
    removed_identifiers = [
        identifier for identifier, key in baseline["identifiers"].items()
        if identifiers.get(identifier) != key
    ]
    changed_contributions = [
        (key, value) for key, value in contributions.items()
        if baseline["contributions"].get(key) != stable_hash(value)
    ]
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            if changed_vulnerabilities:
                cur.executemany(
                    """
                    INSERT INTO vulnerabilities (canonical_id, payload) VALUES (%s, %s)
                    ON CONFLICT (canonical_id) DO UPDATE SET payload = EXCLUDED.payload
                    """,
                    [(key, Jsonb(value)) for key, value in changed_vulnerabilities],
                )
            if removed_identifiers:
                cur.execute(
                    "DELETE FROM vulnerability_ids WHERE identifier = ANY(%s)",
                    (removed_identifiers,),
                )
            if removed_vulnerabilities:
                cur.execute(
                    "DELETE FROM vulnerabilities WHERE canonical_id = ANY(%s)",
                    (list(removed_vulnerabilities),),
                )
            if changed_identifiers:
                cur.executemany(
                    """
                    INSERT INTO vulnerability_ids (identifier, canonical_id) VALUES (%s, %s)
                    ON CONFLICT (identifier) DO UPDATE SET canonical_id = EXCLUDED.canonical_id
                    """,
                    changed_identifiers,
                )
            if changed_contributions:
                cur.executemany(
                    """
                    INSERT INTO source_contributions (contribution_key, payload) VALUES (%s, %s)
                    ON CONFLICT (contribution_key) DO UPDATE SET payload = EXCLUDED.payload
                    """,
                    [(key, Jsonb(value)) for key, value in changed_contributions],
                )
            cur.execute(
                """
                INSERT INTO pipeline_metadata (metadata_key, payload) VALUES ('database', %s)
                ON CONFLICT (metadata_key) DO UPDATE SET payload = EXCLUDED.payload
                """,
                (Jsonb(db.get("meta", {})),),
            )
            if run_id:
                processed_runs = (*processed_runs, run_id)
            if processed_runs:
                cur.executemany(
                    "INSERT INTO processed_runs (run_id) VALUES (%s) ON CONFLICT DO NOTHING",
                    [(processed_run,) for processed_run in processed_runs],
                )
            if audit_event:
                cur.execute(
                    """
                    INSERT INTO security_events
                        (event_key, severity, category, event_type, source, message, target_type,
                         target_id, outcome, actor, details)
                    VALUES (%s, %s, 'feed', %s, %s, %s, 'feed_run', %s, %s, 'vulnerability_pipeline', %s)
                    ON CONFLICT (event_key) DO NOTHING
                    """,
                    (
                        audit_event["event_key"],
                        audit_event["severity"],
                        audit_event["event_type"],
                        audit_event["source"],
                        audit_event["message"],
                        audit_event["target_id"],
                        audit_event["outcome"],
                        Jsonb(audit_event["details"]),
                    ),
                )
    return _baseline(current, contributions)
