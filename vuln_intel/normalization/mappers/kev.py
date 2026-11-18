"""Field mapping: CISA KEV entry -> normalized (enrichment) view."""
from __future__ import annotations

import re

from vuln_intel.normalization.schema import new_view


def normalize_kev(e):
    v = new_view("cisa_kev", e["cveID"], kind="enrichment")
    v["ids"] = [e["cveID"].upper()]
    v["title"], v["description"] = e.get("vulnerabilityName"), e.get("shortDescription")
    v["cwes"] = [c for c in e.get("cwes") or [] if re.fullmatch(r"CWE-\d+", c)]
    v["kev"] = {"vendor_project": e.get("vendorProject"), "product": e.get("product"),
                "date_added": e.get("dateAdded"), "due_date": e.get("dueDate"),
                "required_action": e.get("requiredAction"), "notes": e.get("notes"),
                "known_ransomware_use": e.get("knownRansomwareCampaignUse") == "Known"}
    return v
