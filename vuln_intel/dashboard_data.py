"""Read-only dashboard queries for the PostgreSQL vulnerability store."""
from __future__ import annotations

from vuln_intel import config
from vuln_intel.database import _connect, _ensure_schema


TREND_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _read(query, params=()):
    conn, _ = _connect()
    with conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)
            cur.execute(query, params)
            return cur.fetchall()


def get_summary():
    rows = _read(
        """
        SELECT
            count(*),
            count(*) FILTER (WHERE payload->'exploitation'->>'in_kev' = 'true'),
            count(*) FILTER (WHERE payload->>'severity' = 'CRITICAL'),
            count(*) FILTER (
                WHERE coalesce((payload->'exploitation'->'epss'->>'score')::double precision, 0) >= 0.7
            ),
            count(*) FILTER (WHERE payload->>'severity' = 'HIGH'),
            count(*) FILTER (WHERE payload->>'severity' = 'MEDIUM'),
            count(*) FILTER (WHERE payload->>'severity' = 'LOW'),
            count(*) FILTER (WHERE payload->>'severity' IS NULL OR payload->>'severity' NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
        FROM vulnerabilities
        """
    )
    (total, kev, critical, high_epss, high, medium, low, unknown) = rows[0]
    source_rows = _read(
        """
        SELECT source.name, count(DISTINCT v.canonical_id)
        FROM vulnerabilities AS v
        CROSS JOIN LATERAL jsonb_array_elements_text(v.payload->'sources') AS source(name)
        GROUP BY source.name
        ORDER BY source.name
        """
    )
    risk_rows = _read(
        """
        SELECT payload
        FROM vulnerabilities
        WHERE payload->'exploitation'->>'in_kev' = 'true'
           OR coalesce((payload->'exploitation'->'epss'->>'score')::double precision, 0) >= 0.7
        ORDER BY
            (payload->'exploitation'->>'in_kev' = 'true') DESC,
            coalesce((payload->'exploitation'->'epss'->>'score')::double precision, 0) DESC,
            coalesce((payload->'cvss_best'->>'score')::double precision, 0) DESC
        LIMIT 5
        """
    )
    return {
        "total": total,
        "kev": kev,
        "critical": critical,
        "high_epss": high_epss,
        "severity": {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low, "UNKNOWN": unknown},
        "sources": [{"name": source, "count": count} for source, count in source_rows],
        "top_risk": [payload for (payload,) in risk_rows],
    }


def get_publication_trends():
    rows = _read(
        """
        WITH calendar AS (
            SELECT to_char(month_start, 'YYYY-MM') AS month
            FROM generate_series(
                date_trunc('month', CURRENT_DATE) - interval '11 months',
                date_trunc('month', CURRENT_DATE),
                interval '1 month'
            ) AS calendar_month(month_start)
        ),
        published AS (
            SELECT
                substring(payload->>'published' FROM 1 FOR 7) AS month,
                CASE
                    WHEN payload->>'severity' IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
                    THEN payload->>'severity'
                    ELSE 'UNKNOWN'
                END AS severity,
                count(*) AS total
            FROM vulnerabilities
            WHERE payload->>'published' ~ '^[0-9]{4}-(0[1-9]|1[0-2])-[0-9]{2}'
            GROUP BY 1, 2
        )
        SELECT calendar.month, levels.name, coalesce(published.total, 0)
        FROM calendar
        CROSS JOIN (VALUES
            ('CRITICAL', 1),
            ('HIGH', 2),
            ('MEDIUM', 3),
            ('LOW', 4),
            ('UNKNOWN', 5)
        ) AS levels(name, priority)
        LEFT JOIN published
            ON published.month = calendar.month
            AND published.severity = levels.name
        ORDER BY calendar.month, levels.priority
        """
    )
    months = sorted({month for month, _, _ in rows})
    values = {severity: {month: 0 for month in months} for severity in TREND_SEVERITIES}
    for month, severity, count in rows:
        if severity in values:
            values[severity][month] = count
    return {
        "months": months,
        "series": [
            {"name": severity, "values": [values[severity][month] for month in months]}
            for severity in TREND_SEVERITIES
        ],
    }


def list_vulnerabilities(query="", severity="", exploited=False, page=1, page_size=20):
    conditions, params = [], []
    if query:
        pattern = f"%{query}%"
        conditions.append(
            """(
                v.canonical_id ILIKE %s
                OR coalesce(v.payload->>'title', '') ILIKE %s
                OR coalesce(v.payload->>'description', '') ILIKE %s
                OR EXISTS (
                    SELECT 1 FROM vulnerability_ids AS vi
                    WHERE vi.canonical_id = v.canonical_id AND vi.identifier ILIKE %s
                )
            )"""
        )
        params.extend([pattern] * 4)
    if severity:
        if severity == "UNKNOWN":
            conditions.append("(v.payload->>'severity' IS NULL OR v.payload->>'severity' NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))")
        else:
            conditions.append("v.payload->>'severity' = %s")
            params.append(severity)
    if exploited:
        conditions.append("v.payload->'exploitation'->>'in_kev' = 'true'")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    count_rows = _read(f"SELECT count(*) FROM vulnerabilities AS v {where}", tuple(params))
    total = count_rows[0][0]
    params.extend([page_size, (page - 1) * page_size])
    rows = _read(
        f"""
        SELECT payload
        FROM vulnerabilities AS v
        {where}
        ORDER BY
            (v.payload->'exploitation'->>'in_kev' = 'true') DESC,
            coalesce((v.payload->'exploitation'->'epss'->>'score')::double precision, 0) DESC,
            coalesce((v.payload->'cvss_best'->>'score')::double precision, 0) DESC,
            v.canonical_id
        LIMIT %s OFFSET %s
        """,
        tuple(params),
    )
    return {"items": [payload for (payload,) in rows], "total": total, "page": page, "page_size": page_size}


def get_vulnerability(identifier):
    rows = _read(
        """
        SELECT v.payload
        FROM vulnerabilities AS v
        LEFT JOIN vulnerability_ids AS vi ON vi.canonical_id = v.canonical_id
        WHERE v.canonical_id = %s OR vi.identifier = %s
        LIMIT 1
        """,
        (identifier, identifier),
    )
    return rows[0][0] if rows else None


def get_pipeline_status():
    state = {"sources": {}}
    if config.STATE_PATH.exists():
        from vuln_intel.utils import read_json

        state = read_json(config.STATE_PATH, state)
    return {
        name: {key: source_state[key] for key in ("watermark", "last_success") if key in source_state}
        for name, source_state in state.get("sources", {}).items()
    }
