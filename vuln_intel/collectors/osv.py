"""OSV collector: bulk bucket, incremental via modified_id.csv."""
from __future__ import annotations

import csv
import io
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from vuln_intel import config, http_client
from vuln_intel.utils import parse_ts


def collect_osv(since, until, ctx):
    """OSV bulk bucket: per-ecosystem modified_id.csv lists what changed, then fetch those JSONs."""
    notes, failed, wanted = [], [], []
    for eco in config.OSV_ECOSYSTEMS:
        url = f"{config.OSV_BUCKET}/{urllib.parse.quote(eco, safe='')}/modified_id.csv"
        try:
            body, _ = http_client.http_get(url)
        except Exception as e:  # keep going with the other ecosystems
            failed.append(eco)
            notes.append(f"{eco}: modified_id.csv failed: {e}")
            continue
        for row in csv.reader(io.StringIO(body.decode("utf-8"))):
            if len(row) != 2:
                continue
            ts = parse_ts(row[0])
            if ts and ts > since:
                # rows are 'timestamp,id'; some exports prefix the id with 'Ecosystem/' - accept both
                wanted.append((eco, row[1].strip().rsplit("/", 1)[-1]))

    def fetch(item):
        eco, vid = item
        url = f"{config.OSV_BUCKET}/{urllib.parse.quote(eco, safe='')}/{urllib.parse.quote(vid, safe='')}.json"
        try:
            return json.loads(http_client.http_get(url)[0])
        except Exception as e:
            failed.append(f"{eco}/{vid}")
            notes.append(f"{eco}/{vid}: {e}")
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        fetched = [r for r in pool.map(fetch, wanted) if r]
    latest = {}
    for r in fetched:
        rid = r.get("id")
        if rid and (rid not in latest or (r.get("modified") or "") >= (latest[rid].get("modified") or "")):
            latest[rid] = r
    return {"records": list(latest.values()), "complete": not failed, "notes": notes, "state": {}}
