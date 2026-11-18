"""Field mapping: GitHub advisory -> normalized view."""
from __future__ import annotations

import re

from vuln_intel.normalization.schema import new_view, affected_entry
from vuln_intel.normalization.cvss import make_cvss
from vuln_intel.normalization.versions import parse_constraint_range
from vuln_intel.utils import to_iso


def normalize_ghsa(a):
    v = new_view("ghsa", a["ghsa_id"])
    v["ids"] = [a["ghsa_id"], a.get("cve_id")] + [i.get("value") for i in a.get("identifiers") or []]
    v["title"], v["description"] = a.get("summary"), a.get("description")
    v["published"], v["modified"], v["withdrawn"] = to_iso(a.get("published_at")), to_iso(a["updated_at"]), to_iso(a.get("withdrawn_at"))
    sev = a.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        d = sev.get(key) or {}
        if d.get("vector_string"):
            v["cvss"].append(make_cvss(None, d["vector_string"], d.get("score"), None, "ghsa"))
    legacy = a.get("cvss") or {}
    if legacy.get("vector_string"):
        v["cvss"].append(make_cvss(None, legacy["vector_string"], legacy.get("score"), None, "ghsa"))
    v["vendor_severity"] = a.get("severity")
    v["cwes"] = [c.get("cwe_id") for c in a.get("cwes") or [] if re.fullmatch(r"CWE-\d+", c.get("cwe_id") or "")]
    v["references"] = [r for r in a.get("references") or [] if isinstance(r, str)]
    if a.get("type") == "malware":
        v["tags"].append("malware")
    for vuln in a.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        if not pkg.get("name"):
            continue
        iv = parse_constraint_range(vuln.get("vulnerable_version_range"))
        patched = vuln.get("first_patched_version")
        patched = patched.get("identifier") if isinstance(patched, dict) else patched
        v["affected"].append(affected_entry(pkg.get("ecosystem", ""), pkg["name"], [iv] if iv else [],
                                             patched=[patched]))
    return v
