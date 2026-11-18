"""Normalized record shape ('view') and schema validation."""
from __future__ import annotations

from vuln_intel.normalization.ecosystems import VERSION_SCHEME, std_ecosystem, std_package
from vuln_intel.utils import CVE_RE


def new_view(source, source_id, kind="advisory"):
    return {"source": source, "source_id": source_id, "kind": kind, "key": None, "ids": [],
            "title": None, "description": None, "published": None, "modified": None, "withdrawn": None,
            "cvss": [], "vendor_severity": None, "cwes": [], "affected": [], "references": [],
            "tags": [], "kev": None, "epss": None}


def affected_entry(eco_raw, name, ranges, versions=None, patched=None, **extra):
    eco, release = std_ecosystem(eco_raw)
    return {"ecosystem": eco, "release": release, "package": std_package(eco, name),
            "scheme": VERSION_SCHEME.get(eco, "generic"), "ranges": ranges,
            "versions": sorted(set(versions or [])), "patched": [p for p in (patched or []) if p], **extra}


def validate_view(v):
    """Schema validation on the normalized view. Missing required raw fields raise KeyError earlier."""
    errs = []
    v["ids"] = sorted({i.strip().upper() if CVE_RE.fullmatch(i.strip()) else i.strip()
                       for i in v["ids"] if isinstance(i, str) and i.strip()})
    if not v["source_id"]:
        errs.append("missing source id")
    if not v["ids"]:
        errs.append("no identifiers")
    if v["kind"] == "advisory":
        v["modified"] = v["modified"] or v["published"]
        if not v["modified"]:
            errs.append("no modified/published timestamp")
        for c in v["cvss"]:
            if c.get("score") is not None and not 0 <= c["score"] <= 10:
                errs.append(f"cvss score out of range: {c['score']}")
    if v["epss"] and not (0 <= v["epss"]["score"] <= 1 and 0 <= v["epss"]["percentile"] <= 1):
        errs.append("epss value out of range")
    return errs


def add_unique(lst, item, key):
    if all(x[key] != item[key] for x in lst):
        lst.append(item)
