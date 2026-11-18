"""Shared helpers: timestamps, hashing, JSON file IO."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


UTC = timezone.utc
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)  # use .fullmatch() to validate an ID
_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    """Parse the timestamp formats these sources use into an aware UTC datetime (or None)."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    m = _TS_RE.match(s)
    if not m:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return None
    base, frac, tz = m.groups()
    dt = datetime.strptime(base.replace(" ", "T"), "%Y-%m-%dT%H:%M:%S")
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    offset = timedelta(0)
    if tz and tz != "Z":
        sign = -1 if tz[0] == "-" else 1
        digits = tz[1:].replace(":", "")
        offset = sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return (dt - offset).replace(tzinfo=UTC)


def to_iso(s):
    dt = parse_ts(s)
    return iso(dt) if dt else None


def stable_hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


def read_json(path: Path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)
