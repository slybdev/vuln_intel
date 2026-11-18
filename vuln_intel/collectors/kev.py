"""CISA KEV collector: whole-file download, diffed against the previous snapshot."""
from __future__ import annotations

import json

from vuln_intel import config, http_client
from vuln_intel.utils import stable_hash


def collect_kev(since, until, ctx):
    """CISA KEV: one JSON file, no changelog, so diff each entry against the previous snapshot."""
    catalog = json.loads(http_client.http_get(config.KEV_URL)[0])
    vulns = catalog["vulnerabilities"]
    previous = ctx["state"].get("snapshot", {})
    snapshot = {v["cveID"]: stable_hash(v) for v in vulns}
    changed = [v for v in vulns if previous.get(v["cveID"]) != snapshot[v["cveID"]]]
    note = f"catalogVersion={catalog.get('catalogVersion')} total={len(vulns)} new_or_changed={len(changed)}"
    return {"records": changed, "complete": True, "notes": [note], "state": {"snapshot": snapshot}}
