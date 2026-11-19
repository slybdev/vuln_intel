"""Field mapping: NVD CVE record -> normalized view."""
from __future__ import annotations

import re

from vuln_intel.normalization.schema import new_view, add_unique, affected_entry
from vuln_intel.normalization.cvss import make_cvss
from vuln_intel.normalization.versions import finish_range, parse_constraint_range
from vuln_intel.utils import to_iso


def _nvd_affected_range(version):
    if isinstance(version, str):
        return parse_constraint_range(version)
    if not isinstance(version, dict) or version.get("status") != "affected":
        return None

    raw_version = str(version.get("version") or "").strip()
    parsed = parse_constraint_range(raw_version)
    if parsed:
        return parsed

    introduced = raw_version if raw_version not in ("", "*", "-") else "0"
    fixed = version.get("lessThan")
    last_affected = version.get("lessThanOrEqual")
    if fixed or last_affected:
        interval = {"introduced": introduced}
        if fixed and fixed not in ("*", "-"):
            interval["fixed"] = fixed
        if last_affected and last_affected not in ("*", "-"):
            interval["last_affected"] = last_affected
        return finish_range(interval)
    if introduced == "0":
        return finish_range({"introduced": "0"})
    return finish_range({"introduced": introduced, "last_affected": introduced})


def _cpe_exact_version(version, update):
    if update in ("", "*", "-"):
        return version, False
    if re.fullmatch(r"(?:a|alpha|b|beta|rc)\d*", update, re.IGNORECASE):
        return f"{version}-{update.lower()}", False
    return version, True


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
    for affected in c.get("affected") or []:
        for product_data in affected.get("affectedData") or []:
            vendor, product = product_data.get("vendor"), product_data.get("product")
            if not product:
                continue
            intervals = [
                interval for interval in (
                    _nvd_affected_range(item) for item in product_data.get("versions") or []
                ) if interval
            ]
            if not intervals:
                continue
            ent = acc.setdefault((vendor or product, product, None), affected_entry(
                "cpe", product, [], vendor=vendor or product, cpe_part="a"))
            for interval in intervals:
                add_unique(ent["ranges"], interval, "expr")

    for cfg in c.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = re.split(r"(?<!\\):", m.get("criteria", ""))
                if not m.get("vulnerable") or len(parts) < 6:
                    continue
                part, vendor, product, ver = parts[2], parts[3], parts[4], parts[5]
                update = parts[6] if len(parts) > 6 else "*"
                target_sw = parts[10] if len(parts) > 10 and parts[10] not in ("*", "-") else None
                s_in, s_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                e_in, e_ex = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                if s_in or s_ex or e_in or e_ex:
                    iv = {"introduced": s_in or s_ex or "0", "introduced_exclusive": bool(s_ex and not s_in),
                          "fixed": e_ex, "last_affected": e_in}
                elif ver not in ("*", "-"):
                    ver, unsupported_update = _cpe_exact_version(ver, update)
                    iv = {"introduced": ver, "last_affected": ver}
                    if unsupported_update:
                        iv["cpe_update_unsupported"] = True
                else:
                    iv = {"introduced": "0"}
                ent = acc.setdefault((vendor, product, target_sw), affected_entry(
                    "cpe", product, [], vendor=vendor, cpe_part=part, target_sw=target_sw))
                add_unique(ent["ranges"], finish_range(iv), "expr")
    v["affected"] = list(acc.values())
    return v
