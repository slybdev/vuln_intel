"""Field mapping: NVD CVE record -> normalized view."""
from __future__ import annotations

import re

from vuln_intel.normalization.schema import new_view, add_unique, affected_entry
from vuln_intel.normalization.cvss import make_cvss
from vuln_intel.normalization.versions import finish_range
from vuln_intel.utils import to_iso


def normalize_nvd(c):
    v = new_view("nvd", c["id"])
    v["ids"] = [c["id"].upper()]
    v["description"] = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), None)
    v["published"], v["modified"] = to_iso(c.get("published")), to_iso(c.get("lastModified"))
    if c.get("vulnStatus") == "Rejected":
        v["withdrawn"] = v["modified"]
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in (c.get("metrics") or {}).get(key, []):
            d = m.get("cvssData") or {}
            entry = make_cvss(d.get("version"), d.get("vectorString"), d.get("baseScore"),
                              d.get("baseSeverity") or m.get("baseSeverity"), "nvd")
            entry["primary"] = m.get("type") == "Primary"
            v["cvss"].append(entry)
    for w in c.get("weaknesses") or []:
        for d in w.get("description") or []:
            if re.fullmatch(r"CWE-\d+", d.get("value", "")):
                v["cwes"].append(d["value"])
    v["references"] = [r["url"] for r in c.get("references") or [] if r.get("url")]
    acc = {}
    for cfg in c.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = re.split(r"(?<!\\):", m.get("criteria", ""))
                if not m.get("vulnerable") or len(parts) < 6:
                    continue
                part, vendor, product, ver = parts[2], parts[3], parts[4], parts[5]
                s_in, s_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                e_in, e_ex = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                if s_in or s_ex or e_in or e_ex:
                    iv = {"introduced": s_in or s_ex or "0", "introduced_exclusive": bool(s_ex and not s_in),
                          "fixed": e_ex, "last_affected": e_in}
                elif ver not in ("*", "-"):
                    iv = {"introduced": ver, "last_affected": ver}
                else:
                    iv = {"introduced": "0"}
                ent = acc.setdefault((vendor, product), affected_entry(
                    "cpe", product, [], vendor=vendor, cpe_part=part))
                add_unique(ent["ranges"], finish_range(iv), "expr")
    v["affected"] = list(acc.values())
    return v
