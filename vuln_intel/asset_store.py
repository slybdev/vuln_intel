"""PostgreSQL storage for the managed asset inventory."""
from __future__ import annotations

import uuid

from vuln_intel import event_store
from vuln_intel.database import _connect, _ensure_schema

ASSET_TYPES = {
    "endpoint",
    "server",
    "network_device",
    "operating_system",
    "third_party_application",
    "cloud_resource",
}
ASSET_STATUSES = {"active", "maintenance", "retired", "unknown"}
ASSET_CRITICALITIES = {"critical", "high", "medium", "low", "unknown"}
ASSET_FIELDS = (
    "asset_type",
    "name",
    "identifier",
    "status",
    "environment",
    "owner",
    "location",
    "vendor",
    "model",
    "operating_system",
    "version",
    "ip_address",
    "mac_address",
    "criticality",
    "notes",
)
REQUIRED_FIELDS = {"asset_type", "name", "identifier"}
FIELD_LIMITS = {
    "name": 200,
    "identifier": 255,
    "environment": 100,
    "owner": 200,
    "location": 200,
    "vendor": 120,
    "model": 120,
    "operating_system": 160,
    "version": 120,
    "ip_address": 45,
    "mac_address": 32,
    "notes": 4000,
}
COLUMNS = ("asset_id",) + ASSET_FIELDS + ("created_at", "updated_at")


class AssetConflict(ValueError):
    """Raised when an asset identifier already exists for its type."""


def _validated_fields(payload: dict, partial: bool = False) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("Asset data must be a JSON object.")
    if not payload:
        raise ValueError("At least one asset field must be provided.")
    unknown = set(payload) - set(ASSET_FIELDS)
    if unknown:
        raise ValueError(f"Unknown asset field: {sorted(unknown)[0]}.")
    if not partial:
        missing = REQUIRED_FIELDS - set(payload)
        if missing:
            raise ValueError(f"Required asset field is missing: {sorted(missing)[0]}.")
    result = {}
    for field, value in payload.items():
        if field in {"asset_type", "status", "criticality"}:
            allowed = {
                "asset_type": ASSET_TYPES,
                "status": ASSET_STATUSES,
                "criticality": ASSET_CRITICALITIES,
            }[field]
            if field not in payload and partial:
                continue
            if not isinstance(value, str) or value not in allowed:
                raise ValueError(f"Invalid {field.replace('_', ' ')}.")
            result[field] = value
            continue
        if value is None and field not in REQUIRED_FIELDS:
            value = ""
        if not isinstance(value, str):
            raise TypeError(f"{field.replace('_', ' ').capitalize()} must be text.")
        value = value.strip()
        limit = FIELD_LIMITS.get(field)
        if limit is not None and len(value) > limit:
            raise ValueError(f"{field.replace('_', ' ').capitalize()} must be at most {limit} characters.")
        if field in REQUIRED_FIELDS and not value:
            raise ValueError(f"{field.replace('_', ' ').capitalize()} is required.")
        result[field] = value
    if not partial:
        result.setdefault("status", "active")
        result.setdefault("criticality", "unknown")
        for field in ASSET_FIELDS:
            result.setdefault(field, "")
    return result


def _as_asset(row):
    return dict(zip(COLUMNS, row)) if row else None


def _translate_conflict(exc):
    if getattr(exc, "sqlstate", None) == "23505":
        raise AssetConflict("An asset with this identifier and type already exists.") from exc
    raise exc


def list_assets(query="", asset_type="", status="", page=1, page_size=25):
    conditions, params = [], []
    if query:
        pattern = f"%{query}%"
        conditions.append(
            "(name ILIKE %s OR identifier ILIKE %s OR owner ILIKE %s "
            "OR location ILIKE %s OR vendor ILIKE %s OR operating_system ILIKE %s)"
        )
        params.extend([pattern] * 6)
    if asset_type:
        conditions.append("asset_type = %s")
        params.append(asset_type)
    if status:
        conditions.append("status = %s")
        params.append(status)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(f"SELECT count(*) FROM assets {where}", tuple(params))
            total = cur.fetchone()[0]
            cur.execute(
                f"""
                SELECT {", ".join(COLUMNS)}
                FROM assets
                {where}
                ORDER BY updated_at DESC, asset_id
                LIMIT %s OFFSET %s
                """,
                tuple(params + [page_size, (page - 1) * page_size]),
            )
            items = [_as_asset(row) for row in cur.fetchall()]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def get_asset_summary():
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                """
                SELECT
                    count(*),
                    count(*) FILTER (WHERE status = 'active'),
                    count(*) FILTER (WHERE status IN ('maintenance', 'unknown')),
                    count(DISTINCT asset_type)
                FROM assets
                """
            )
            total, active, attention, types = cur.fetchone()
    return {"total": total, "active": active, "attention": attention, "types": types}


def create_asset(payload):
    fields = _validated_fields(payload)
    asset_id = str(uuid.uuid4())
    conn, Jsonb = _connect()
    try:
        with conn:
            with conn.cursor() as cur:
                _ensure_schema(cur)
                cur.execute(
                    f"""
                    INSERT INTO assets (asset_id, {", ".join(ASSET_FIELDS)})
                    VALUES (%s, {", ".join(["%s"] * len(ASSET_FIELDS))})
                    RETURNING {", ".join(COLUMNS)}
                    """,
                    (asset_id, *(fields[field] for field in ASSET_FIELDS)),
                )
                row = cur.fetchone()
                event_store.insert_event(
                    cur,
                    Jsonb,
                    severity="INFO",
                    category="asset",
                    event_type="asset.registered",
                    source="Asset inventory",
                    message=f"Asset registered: {fields['name']}",
                    target_type="asset",
                    target_id=asset_id,
                    outcome="succeeded",
                    actor="local_operator",
                    details={
                        "asset_type": fields["asset_type"],
                        "identifier": fields["identifier"],
                    },
                )
    except Exception as exc:
        _translate_conflict(exc)
    return _as_asset(row)


def get_asset(asset_id):
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                f"SELECT {', '.join(COLUMNS)} FROM assets WHERE asset_id = %s",
                (asset_id,),
            )
            return _as_asset(cur.fetchone())


def update_asset(asset_id, payload):
    fields = _validated_fields(payload, partial=True)
    conn, Jsonb = _connect()
    try:
        with conn:
            with conn.cursor() as cur:
                _ensure_schema(cur)
                cur.execute(
                    f"""
                    UPDATE assets
                    SET {", ".join(f"{field} = %s" for field in fields)},
                        updated_at = now()
                    WHERE asset_id = %s
                    RETURNING {", ".join(COLUMNS)}
                    """,
                    (*fields.values(), asset_id),
                )
                row = cur.fetchone()
                if row:
                    event_store.insert_event(
                        cur,
                        Jsonb,
                        severity="INFO",
                        category="asset",
                        event_type="asset.updated",
                        source="Asset inventory",
                        message=f"Asset updated: {row[2]}",
                        target_type="asset",
                        target_id=asset_id,
                        outcome="updated",
                        actor="local_operator",
                        details={"changed_fields": sorted(fields)},
                    )
    except Exception as exc:
        _translate_conflict(exc)
    return _as_asset(row)


def delete_asset(asset_id):
    conn, Jsonb = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(
                "DELETE FROM assets WHERE asset_id = %s RETURNING asset_type, name",
                (asset_id,),
            )
            row = cur.fetchone()
            if row:
                event_store.insert_event(
                    cur,
                    Jsonb,
                    severity="INFO",
                    category="asset",
                    event_type="asset.deleted",
                    source="Asset inventory",
                    message=f"Asset removed: {row[1]}",
                    target_type="asset",
                    target_id=asset_id,
                    outcome="deleted",
                    actor="local_operator",
                    details={"asset_type": row[0]},
                )
            return row is not None
