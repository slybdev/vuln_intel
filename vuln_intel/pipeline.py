"""Orchestration: collection run and processing run."""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from vuln_intel import config, event_store
from vuln_intel.collectors import COLLECTORS, ORDER, touched_cves
from vuln_intel import database
from vuln_intel.normalization.mappers import NORMALIZERS
from vuln_intel.normalization.resolver import Store, expand_views
from vuln_intel.normalization.schema import validate_view
from vuln_intel.reporting import write_report
from vuln_intel.utils import CVE_RE, iso, parse_ts, read_json, utcnow, write_json


log = logging.getLogger(__name__)


def run_collect(sources, since_override=None):
    started = utcnow()
    run_id = started.strftime("%Y%m%dT%H%M%SZ")
    state = read_json(config.STATE_PATH, {"sources": {}, "processed_runs": []})
    if config.DATABASE_URL:
        existing_cves = database.load_existing_cves()
    else:
        db = read_json(config.DB_PATH, {"vulnerabilities": {}})
        existing_cves = {i for e in db["vulnerabilities"].values() for i in e["ids"] if CVE_RE.fullmatch(i)}
    ctx = {"epss_cves": set(existing_cves), "state": {}}
    summary, any_failed = {}, False

    for name in [s for s in ORDER if s in sources]:
        src_state = state["sources"].setdefault(name, {})
        ctx["state"] = src_state
        if since_override:
            since = since_override
        elif src_state.get("watermark"):
            since = parse_ts(src_state["watermark"]) - timedelta(hours=config.OVERLAP_HOURS)
        else:
            since = started - timedelta(hours=config.FIRST_RUN_LOOKBACK_HOURS)
        log.info("[%s] collecting window %s -> %s", name, iso(since), iso(started))
        try:
            res = COLLECTORS[name](since, started, ctx)
        except Exception as e:
            any_failed = True
            summary[name] = {"count": 0, "complete": False, "error": str(e)}
            log.error("[%s] FAILED: %s", name, e)
            continue
        write_json(config.DATA_DIR / "raw" / run_id / f"{name}.json", {
            "source": name, "run_id": run_id, "collected_at": iso(utcnow()),
            "window": {"since": iso(since), "until": iso(started)},
            "complete": res["complete"], "notes": res["notes"],
            "count": len(res["records"]), "records": res["records"]})
        ctx["epss_cves"] |= touched_cves(name, res["records"])
        if res["complete"]:
            src_state["watermark"] = iso(started)  # advance only on full success
            src_state["last_success"] = iso(utcnow())
            src_state.update(res["state"])
        else:
            any_failed = True
            log.warning("[%s] partial result; watermark NOT advanced", name)
        summary[name] = {"count": len(res["records"]), "complete": res["complete"], "notes": res["notes"][:5]}
        log.info("[%s] %d records", name, len(res["records"]))

    write_json(config.STATE_PATH, state)
    config.DATA_DIR.joinpath("logs").mkdir(parents=True, exist_ok=True)
    with open(config.DATA_DIR / "logs" / "runs.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"run_id": run_id, "started": iso(started), "finished": iso(utcnow()),
                            "sources": summary}) + "\n")
    if config.DATABASE_URL:
        for source, result in summary.items():
            complete = result["complete"]
            outcome = "succeeded" if complete else (
                "partial" if result.get("count", 0) else "failed"
            )
            event_store.record_event(
                severity="INFO" if complete else ("HIGH" if outcome == "failed" else "MEDIUM"),
                category="feed",
                event_type="feed.collection",
                source=f"{source.upper()} feed",
                message=(
                    f"{source.upper()} feed collection {outcome}: "
                    f"{result.get('count', 0)} records"
                ),
                target_type="feed",
                target_id=source,
                outcome=outcome,
                actor="vulnerability_pipeline",
                details={
                    "run_id": run_id,
                    "record_count": result.get("count", 0),
                    "complete": complete,
                },
                event_key=f"feed:{run_id}:{source}",
            )
    return run_id, any_failed


def run_process(only_runs=None):
    state = read_json(config.STATE_PATH, {"sources": {}, "processed_runs": []})
    if config.DATABASE_URL:
        db, contribs, processed_runs, baseline = database.load_snapshot()
        processed_runs.update(state["processed_runs"])
    else:
        db = read_json(config.DB_PATH, {"meta": {}, "vulnerabilities": {}})
        contribs = read_json(config.CONTRIB_PATH, {})
        processed_runs = set(state["processed_runs"])
    raw_root = config.DATA_DIR / "raw"
    pending = only_runs or sorted(d.name for d in raw_root.glob("*")
                                  if d.is_dir() and d.name not in processed_runs)
    if not pending:
        log.info("No unprocessed raw runs.")
        return
    for run_id in pending:
        now = utcnow()
        store, counts, rejected, notes = Store(db, contribs, now), {}, [], []
        for src in ORDER:
            f = raw_root / run_id / f"{src}.json"
            if not f.exists():
                continue
            env = read_json(f, {})
            notes += [f"[{src}] {n}" for n in env.get("notes", [])]
            counts[src] = len(env.get("records", []))
            for raw in env.get("records", []):
                try:
                    view = NORMALIZERS[src](raw)
                    errors = validate_view(view)
                    if errors:
                        raise ValueError("; ".join(errors))
                except Exception as e:  # one bad record must not stop the run
                    rejected.append({"source": src, "reason": f"{type(e).__name__}: {e}",
                                     "record_id": str(raw.get("id") or raw.get("ghsa_id") or raw.get("cveID") or raw.get("cve")
                                                      or "?")})
                    continue
                for v in expand_views(view):
                    store.upsert(v)
        store.finalize()
        db["meta"] = {"generated_at": iso(utcnow()), "entity_count": len(db["vulnerabilities"]),
                      "last_run": run_id, "schema_version": 1}
        if config.DATABASE_URL:
            rejected_count = len(rejected)
            outcome = "partial" if rejected_count else "succeeded"
            baseline = database.save_snapshot(
                db,
                contribs,
                run_id,
                baseline=baseline,
                audit_event={
                    "event_key": f"feed-process:{run_id}",
                    "severity": "MEDIUM" if rejected_count else "INFO",
                    "event_type": "feed.records_processed",
                    "source": "Vulnerability normalization",
                    "message": (
                        f"Processed vulnerability feed records: {len(store.new_ids)} new, "
                        f"{len(store.changed_ids)} updated, {rejected_count} rejected"
                    ),
                    "target_id": run_id,
                    "outcome": outcome,
                    "details": {
                        "run_id": run_id,
                        "new": len(store.new_ids),
                        "updated": len(store.changed_ids),
                        "rejected": rejected_count,
                        "entity_count": len(db["vulnerabilities"]),
                    },
                },
            )
            processed_runs.add(run_id)
        else:
            write_json(config.DB_PATH, db)
            write_json(config.CONTRIB_PATH, contribs)
        if rejected:
            write_json(config.DATA_DIR / "rejected" / f"{run_id}.json", rejected)
        if run_id not in state["processed_runs"]:
            state["processed_runs"].append(run_id)
        write_json(config.STATE_PATH, state)
        report = write_report(run_id, store, counts, rejected, notes)
        log.info("Processed %s: %s | new=%d updated=%d rejected=%d -> %s", run_id, store.stats,
                 len(store.new_ids), len(store.changed_ids), len(rejected), report)
