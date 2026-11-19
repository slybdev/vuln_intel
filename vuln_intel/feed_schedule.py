"""Persistence and execution for the daily external-feed refresh schedule."""
from __future__ import annotations

import logging
import re
from datetime import datetime, time, timedelta, timezone
from threading import Event, Lock, Thread
from uuid import uuid4

from vuln_intel import config, database, event_store
from vuln_intel.collectors import ORDER
from vuln_intel.pipeline import run_collect, run_process

log = logging.getLogger(__name__)
_TIME_PATTERN = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
_POLL_INTERVAL_SECONDS = 15
_worker_lock = Lock()
_worker_stop = Event()
_worker: Thread | None = None


def _next_run_at(run_time: time, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    candidate = datetime.combine(now.date(), run_time, tzinfo=timezone.utc)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def _serialize(row):
    if row is None:
        return None
    enabled, run_time, next_run_at, last_run_at, status, error, summary = row
    return {
        "enabled": enabled,
        "time": run_time.strftime("%H:%M"),
        "next_run_at": next_run_at,
        "last_run_at": last_run_at,
        "last_run_status": status,
        "last_run_error": error,
        "last_run_summary": summary or {},
    }


def get_schedule():
    conn, _ = database._connect()
    with conn:
        with conn.cursor() as cur:
            database._ensure_schema(cur)
            cur.execute(
                """
                SELECT enabled, run_time, next_run_at, last_run_at,
                       last_run_status, last_run_error, last_run_summary
                FROM feed_update_schedule
                WHERE schedule_id = 1
                """
            )
            return _serialize(cur.fetchone())


def save_schedule(enabled, run_time_text):
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean.")
    if not isinstance(run_time_text, str) or not _TIME_PATTERN.fullmatch(run_time_text):
        raise ValueError("time must use 24-hour HH:MM format.")
    run_time = datetime.strptime(run_time_text, "%H:%M").time()
    conn, Jsonb = database._connect()
    with conn:
        with conn.cursor() as cur:
            database._ensure_schema(cur)
            cur.execute("SELECT now()")
            next_run_at = (
                _next_run_at(run_time, cur.fetchone()[0]) if enabled else None
            )
            cur.execute(
                """
                INSERT INTO feed_update_schedule
                    (schedule_id, enabled, run_time, next_run_at, last_run_status,
                     last_run_error, last_run_summary, updated_at)
                VALUES (1, %s, %s, %s, NULL, NULL, '{}'::jsonb, now())
                ON CONFLICT (schedule_id) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    run_time = EXCLUDED.run_time,
                    next_run_at = EXCLUDED.next_run_at,
                    updated_at = now()
                """,
                (enabled, run_time, next_run_at),
            )
            event_store.insert_event(
                cur,
                Jsonb,
                severity="INFO",
                category="settings",
                event_type="feed.schedule.updated",
                source="Scheduled feed update",
                message=(
                    "Daily external vulnerability feed refresh enabled"
                    if enabled
                    else "Daily external vulnerability feed refresh paused"
                ),
                target_type="feed_schedule",
                target_id="external_osint",
                outcome="updated",
                actor="local_operator",
                details={"enabled": enabled, "time_utc": run_time_text},
                event_key=f"feed-schedule:updated:{uuid4().hex}",
            )
            cur.execute(
                """
                SELECT enabled, run_time, next_run_at, last_run_at,
                       last_run_status, last_run_error, last_run_summary
                FROM feed_update_schedule
                WHERE schedule_id = 1
                """
            )
            return _serialize(cur.fetchone())


def _claim_due_schedule():
    conn, _ = database._connect()
    with conn:
        with conn.cursor() as cur:
            database._ensure_schema(cur)
            cur.execute(
                """
                SELECT run_time, now()
                FROM feed_update_schedule
                WHERE schedule_id = 1 AND enabled AND next_run_at <= now()
                FOR UPDATE SKIP LOCKED
                """
            )
            row = cur.fetchone()
            if row is None:
                return None
            run_time, now = row
            next_run_at = datetime.combine(now.date(), run_time, tzinfo=timezone.utc)
            if next_run_at <= now:
                next_run_at += timedelta(days=1)
            cur.execute(
                """
                UPDATE feed_update_schedule
                SET next_run_at = %s,
                    last_run_at = %s,
                    last_run_status = 'running',
                    last_run_error = NULL,
                    last_run_summary = '{}'::jsonb,
                    updated_at = now()
                WHERE schedule_id = 1
                """,
                (next_run_at, now),
            )
            return now


def _finish_run(scheduled_at, status, run_id=None, error=None):
    summary = {"run_id": run_id, "feed_count": len(ORDER)}
    conn, Jsonb = database._connect()
    with conn:
        with conn.cursor() as cur:
            database._ensure_schema(cur)
            cur.execute(
                """
                UPDATE feed_update_schedule
                SET last_run_status = %s,
                    last_run_error = %s,
                    last_run_summary = %s,
                    updated_at = now()
                WHERE schedule_id = 1 AND last_run_at = %s
                """,
                (status, error, Jsonb(summary), scheduled_at),
            )
            event_store.insert_event(
                cur,
                Jsonb,
                severity="HIGH" if status == "failed" else (
                    "MEDIUM" if status == "partial" else "INFO"
                ),
                category="feed",
                event_type="feed.scheduled_update",
                source="Scheduled feed update",
                message=f"Daily external vulnerability feed refresh {status}",
                target_type="feed_schedule",
                target_id="external_osint",
                outcome=status,
                actor="vulnerability_pipeline",
                details=summary,
                event_key=f"feed-schedule:run:{scheduled_at.isoformat()}",
            )


def run_due_schedule() -> bool:
    scheduled_at = _claim_due_schedule()
    if scheduled_at is None:
        return False
    run_id = None
    try:
        run_id, incomplete = run_collect(set(ORDER))
        run_process(only_runs=[run_id])
        status = "partial" if incomplete else "succeeded"
        error = (
            "One or more external feeds returned incomplete data. Review Security Logs."
            if incomplete
            else None
        )
    except Exception:
        log.exception("Scheduled external vulnerability feed refresh failed.")
        status = "failed"
        error = "Scheduled feed refresh failed. Check the backend logs for details."
    _finish_run(scheduled_at, status, run_id, error)
    return True


def _worker_loop():
    while not _worker_stop.is_set():
        try:
            run_due_schedule()
        except Exception:
            log.exception("Could not check the external feed update schedule.")
        if _worker_stop.wait(_POLL_INTERVAL_SECONDS):
            break


def start_worker():
    if not config.DATABASE_URL:
        raise RuntimeError("Daily feed scheduling requires PostgreSQL.")
    global _worker
    with _worker_lock:
        if _worker and _worker.is_alive():
            return
        _worker_stop.clear()
        _worker = Thread(
            target=_worker_loop,
            name="external-feed-scheduler",
            daemon=True,
        )
        _worker.start()


def stop_worker():
    _worker_stop.set()
    worker = _worker
    if worker and worker.is_alive():
        worker.join(timeout=_POLL_INTERVAL_SECONDS + 1)
