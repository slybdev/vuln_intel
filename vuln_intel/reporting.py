"""Human-readable run report."""
from __future__ import annotations

from vuln_intel import config


def _priority(e):
    expl = e.get("exploitation") or {}
    epss = (expl.get("epss") or {}).get("score") or 0
    cvss = (e.get("cvss_best") or {}).get("score") or 0
    return (expl.get("in_kev", False), epss, cvss)


def write_report(run_id, store, counts, rejected, notes):
    ents = store.ents
    touched = [ents[i] for i in dict.fromkeys(store.new_ids + store.changed_ids) if i in ents]
    kev_new = [e for e in touched if e["exploitation"]["in_kev"]]
    lines = [f"VULNERABILITY INTELLIGENCE REPORT  run {run_id}", "=" * 72, "",
             "Raw records processed per source:"]
    lines += [f"  {s:<6} {n}" for s, n in counts.items()] or ["  (none)"]
    lines += ["", f"Entities in database      : {len(ents)}",
              f"New entities this run     : {len(store.new_ids)}",
              f"Updated entities this run : {len(store.changed_ids)}",
              f"Contribution results      : {store.stats}",
              f"Rejected by validation    : {len(rejected)}"]
    if notes:
        lines += ["", "Source notes:"] + [f"  {n}" for n in notes]
    lines += ["", f"Touched entities that are in CISA KEV ({len(kev_new)}):"]
    for e in sorted(kev_new, key=_priority, reverse=True)[:25]:
        lines.append(f"  {e['id']:<18} {(e.get('title') or e.get('description') or '')[:70]}")
    lines += ["", "Top 15 touched entities by priority (KEV, then EPSS, then CVSS):"]
    for e in sorted(touched, key=_priority, reverse=True)[:15]:
        x = e["exploitation"]
        epss = (x["epss"] or {}).get("score")
        cvss = (e.get("cvss_best") or {}).get("score")
        lines.append(f"  {e['id']:<18} KEV={'Y' if x['in_kev'] else 'n'}  "
                     f"EPSS={epss if epss is not None else '-'}  CVSS={cvss if cvss is not None else '-'}  "
                     f"{e.get('severity') or '-'}")
    path = config.DATA_DIR / "reports" / f"report_{run_id}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
