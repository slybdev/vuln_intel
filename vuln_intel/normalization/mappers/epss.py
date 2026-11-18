"""Field mapping: EPSS score row -> normalized (enrichment) view."""
from __future__ import annotations

from vuln_intel.normalization.schema import new_view


def normalize_epss(r):
    v = new_view("epss", r["cve"], kind="enrichment")
    v["ids"] = [r["cve"].upper()]
    v["epss"] = {"score": float(r["epss"]), "percentile": float(r["percentile"]),
                 "date": (r.get("score_date") or "")[:10] or None}
    return v
