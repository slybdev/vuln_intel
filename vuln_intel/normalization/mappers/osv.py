"""Field mapping: OSV record -> normalized view."""
from __future__ import annotations

import re

from vuln_intel.normalization.schema import new_view, affected_entry
from vuln_intel.normalization.cvss import make_cvss
from vuln_intel.normalization.versions import osv_events_to_intervals
from vuln_intel.utils import to_iso


def normalize_osv(r):
    v = new_view("osv", r["id"])
    v["ids"] = [r["id"]] + [a for a in r.get("aliases") or []]
    v["title"], v["description"] = r.get("summary"), r.get("details")
    v["published"], v["modified"], v["withdrawn"] = to_iso(r.get("published")), to_iso(r["modified"]), to_iso(r.get("withdrawn"))
    for s in r.get("severity") or []:
        v["cvss"].append(make_cvss(None, s.get("score"), None, None, "osv"))
    dbs = r.get("database_specific") or {}
    v["vendor_severity"] = dbs.get("severity")
    v["cwes"] = [c for c in dbs.get("cwe_ids") or [] if re.fullmatch(r"CWE-\d+", c)]
    v["references"] = [x["url"] for x in r.get("references") or [] if x.get("url")]
    for a in r.get("affected") or []:
        pkg = a.get("package") or {}
        if not pkg.get("name"):
            continue
        ranges = []
        for rng in a.get("ranges") or []:
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):  # GIT ranges are commit based; skipped
                ranges += osv_events_to_intervals(rng.get("events"))
        v["affected"].append(affected_entry(pkg.get("ecosystem", ""), pkg["name"], ranges,
                                             a.get("versions"), purl=pkg.get("purl")))
    return v
