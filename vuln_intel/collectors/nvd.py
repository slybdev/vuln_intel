"""NVD CVE API 2.0 collector (incremental, by last-modified window)."""
from __future__ import annotations

import time
from datetime import datetime, timedelta

from vuln_intel import config, http_client
from vuln_intel.utils import UTC


def _nvd_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def collect_nvd(since, until, ctx):
    """NVD CVE API 2.0, filtered by last-modified window (max 120 days per request)."""
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    pause = 0.8 if config.NVD_API_KEY else 6.5  # ~50 req/30s with key, ~5 req/30s without
    found = {}
    start = since
    while start < until:
        end = min(start + timedelta(days=119), until)
        index = 0
        while True:
            data = http_client.get_json(config.NVD_URL, headers, {
                "lastModStartDate": _nvd_ts(start), "lastModEndDate": _nvd_ts(end),
                "resultsPerPage": 2000, "startIndex": index,
            }, retry_status=(403, 429, 500, 502, 503, 504))  # NVD sometimes answers 403 when throttled
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                cve = v["cve"]
                found[cve["id"]] = cve
            index += len(vulns)
            if not vulns or index >= data.get("totalResults", 0):
                break
            time.sleep(pause)
        start = end
        if start < until:
            time.sleep(pause)
    return {"records": list(found.values()), "complete": True, "notes": [], "state": {}}
