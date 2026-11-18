"""EPSS collector: daily bulk CSV, filtered to the CVEs we care about."""
from __future__ import annotations

import csv
import gzip
import re

from vuln_intel import config, http_client


def collect_epss(since, until, ctx):
    """EPSS daily CSV. Only keeps scores for CVEs touched this run plus every CVE already in the DB."""
    wanted = ctx["epss_cves"]
    body, _ = http_client.http_get(config.EPSS_URL, timeout=180)
    for _ in range(2):  # tolerate a transport layer that already gunzipped, or a double gzip
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
    text = body.decode("utf-8")
    score_date = None
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            m = re.search(r"score_date:([^,\s]+)", line)
            if m:
                score_date = m.group(1)
        elif line.strip():
            lines.append(line)
    records = []
    for row in csv.DictReader(lines):
        cve = (row.get("cve") or "").strip().upper()
        if cve in wanted:
            records.append({"cve": cve, "epss": float(row["epss"]),
                            "percentile": float(row["percentile"]), "score_date": score_date})
    return {"records": records, "complete": True,
            "notes": [f"score_date={score_date} wanted={len(wanted)} matched={len(records)}"], "state": {}}
