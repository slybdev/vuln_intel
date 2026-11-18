"""HTTP GET with retry/backoff, standard library only."""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request


log = logging.getLogger(__name__)


def http_get(url, headers=None, params=None, retries=5, timeout=90,
             retry_status=(429, 500, 502, 503, 504)):
    """GET with exponential backoff. Returns (body_bytes, lower-cased response headers)."""
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    hdrs = {"User-Agent": "vuln-intel-pipeline/1.0", **(headers or {})}
    delay = 2.0
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            if e.code in retry_status and attempt < retries:
                try:
                    wait = float(e.headers.get("Retry-After", delay))
                except (TypeError, ValueError):
                    wait = delay
                log.warning("HTTP %s from %s - retry %d in %.0fs", e.code, url[:90], attempt, wait)
                time.sleep(wait)
                delay *= 2
                continue
            raise RuntimeError(f"HTTP {e.code} for {url}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < retries:
                log.warning("Network error %s - retry %d in %.0fs", e, attempt, delay)
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"Network error for {url}: {e}") from e


def get_json(url, headers=None, params=None, **kw):
    body, _ = http_get(url, headers, params, **kw)
    return json.loads(body)
