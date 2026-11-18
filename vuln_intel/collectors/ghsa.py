"""GitHub Security Advisories collector (REST, `modified` filter, Link-header paging)."""
from __future__ import annotations

import json
import re
import urllib.parse

from vuln_intel import config, http_client


def _next_link(link_header):
    m = re.search(r'<([^>]+)>\s*;\s*rel="next"', link_header or "")
    return m.group(1) if m else None


def collect_ghsa(since, until, ctx):
    """GitHub global advisories REST API (`modified` filter is date-granular; overlap is deduped later)."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    found = {}
    for adv_type in config.GHSA_TYPES:
        params = {"modified": f">={since:%Y-%m-%d}", "type": adv_type, "per_page": 100,
                  "sort": "updated", "direction": "desc"}
        url = f"{config.GHSA_URL}?{urllib.parse.urlencode(params)}"
        while url:
            body, resp_headers = http_client.http_get(url, headers)
            for adv in json.loads(body):
                found[adv["ghsa_id"]] = adv
            url = _next_link(resp_headers.get("link"))
    return {"records": list(found.values()), "complete": True, "notes": [], "state": {}}
