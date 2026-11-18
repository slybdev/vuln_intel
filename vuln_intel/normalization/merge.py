"""Merge every source's view of one entity into one standardized record."""
from __future__ import annotations

from vuln_intel.normalization.schema import add_unique


SRC_RANK = {"nvd": 0, "ghsa": 1, "osv": 2, "cisa_kev": 3, "epss": 4}


_CVSS_VERSION_RANK = {"3.1": 0, "3.0": 1, "4.0": 2, "2.0": 3}


def merge_views(views):
    """Combine all per-source views of one entity into one standardized record."""
    views = sorted(views, key=lambda v: (SRC_RANK.get(v["source"], 9), v["source_id"]))
    adv = [v for v in views if v["kind"] == "advisory"]

    def pick(field, order):
        for src in order:
            for v in views:
                if v["source"] == src and v.get(field):
                    return v[field]
        return None

    stamps = lambda f: [v[f] for v in adv if v.get(f)]  # noqa: E731 - ISO strings sort chronologically
    cvss, seen = [], set()
    for v in views:
        for c in v["cvss"]:
            k = (c["version"], c["vector"])
            if k not in seen and (c["vector"] or c["score"] is not None):
                seen.add(k)
                cvss.append(c)
    cvss.sort(key=lambda c: (_CVSS_VERSION_RANK.get(c["version"], 9), not c.get("primary"),
                             SRC_RANK.get(c["provider"], 9)))
    best = next((c for c in cvss if c.get("score") is not None), None)
    vendor_sev = next((v["vendor_severity"] for v in views if v.get("vendor_severity")), None)
    vendor_sev = (vendor_sev or "").upper() or None
    severity = best["severity"] if best else ("MEDIUM" if vendor_sev == "MODERATE" else vendor_sev)

    acc = {}
    for v in adv:
        for a in v["affected"]:
            k = (a["ecosystem"], a.get("release"), a.get("vendor"), a["package"])
            e = acc.setdefault(k, {**{x: y for x, y in a.items() if x not in ("ranges", "versions", "patched")},
                                   "ranges": [], "versions": [], "patched": [], "sources": []})
            for r in a["ranges"]:
                add_unique(e["ranges"], r, "expr")
            e["versions"] = sorted(set(e["versions"]) | set(a["versions"]))
            e["patched"] = sorted(set(e["patched"]) | set(a["patched"]))
            e["sources"] = sorted(set(e["sources"]) | {v["source"]})
    affected = []
    for k in sorted(acc, key=lambda k: tuple(str(x or "") for x in k)):
        acc[k]["ranges"].sort(key=lambda r: r["expr"])
        affected.append(acc[k])

    refs = list(dict.fromkeys(r.strip() for v in views for r in v["references"] if r and r.strip()))
    kev = next((v["kev"] for v in views if v.get("kev")), None)
    epss = max((v["epss"] for v in views if v.get("epss")), key=lambda e: e["date"] or "", default=None)
    return {
        "title": pick("title", ["ghsa", "osv", "cisa_kev"]),
        "description": pick("description", ["nvd", "ghsa", "osv", "cisa_kev"]),
        "published": min(stamps("published"), default=None),
        "modified": max(stamps("modified"), default=None),
        "withdrawn": min(stamps("withdrawn"), default=None),
        "severity": severity,
        "cvss_best": best,
        "cvss": cvss,
        "cwes": sorted({c for v in views for c in v["cwes"]}),
        "affected": affected,
        "references": refs,
        "tags": sorted({t for v in views for t in v["tags"]}),
        "exploitation": {"in_kev": kev is not None, "kev": kev, "epss": epss},
    }
