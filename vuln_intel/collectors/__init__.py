"""Source collectors. Each returns {"records", "complete", "notes", "state"}."""
from __future__ import annotations

from vuln_intel.collectors.epss import collect_epss
from vuln_intel.collectors.ghsa import collect_ghsa
from vuln_intel.collectors.kev import collect_kev
from vuln_intel.collectors.nvd import collect_nvd
from vuln_intel.collectors.osv import collect_osv
from vuln_intel.utils import CVE_RE

# EPSS runs last: it enriches the CVEs the other collectors found.
COLLECTORS = {"nvd": collect_nvd, "osv": collect_osv, "ghsa": collect_ghsa,
              "kev": collect_kev, "epss": collect_epss}
ORDER = list(COLLECTORS)


def touched_cves(source, records):
    found = set()
    for r in records:
        if source == "nvd":
            cands = [r.get("id")]
        elif source == "osv":
            cands = [r.get("id")] + list(r.get("aliases") or [])
        elif source == "ghsa":
            cands = [r.get("cve_id")] + [i.get("value") for i in (r.get("identifiers") or [])]
        elif source == "kev":
            cands = [r.get("cveID")]
        else:
            cands = []
        found.update(c.upper() for c in cands if c and CVE_RE.fullmatch(c))
    return found
