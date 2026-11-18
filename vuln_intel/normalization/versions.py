"""Version-range standardization: one interval shape for every source."""
from __future__ import annotations

import re


def range_expr(iv):
    intro, parts = iv.get("introduced"), []
    if intro and intro == iv.get("last_affected") and not iv.get("introduced_exclusive"):
        return f"=={intro}"
    if intro and intro != "0":
        parts.append((">" if iv.get("introduced_exclusive") else ">=") + intro)
    if iv.get("fixed"):
        parts.append("<" + iv["fixed"])
    if iv.get("last_affected"):
        parts.append("<=" + iv["last_affected"])
    return ", ".join(parts) or "*"


def finish_range(iv):
    iv = {k: v for k, v in iv.items() if v not in (None, False)}
    iv.setdefault("introduced", "0")
    iv["expr"] = range_expr(iv)
    return iv


def osv_events_to_intervals(events):
    intervals, cur = [], None
    for ev in events or []:
        if "introduced" in ev:
            if cur:
                intervals.append(cur)
            cur = {"introduced": ev["introduced"]}
        elif "fixed" in ev or "last_affected" in ev:
            cur = cur or {"introduced": "0"}
            cur["fixed" if "fixed" in ev else "last_affected"] = ev.get("fixed") or ev.get("last_affected")
            intervals.append(cur)
            cur = None
    if cur:
        intervals.append(cur)
    return [finish_range(i) for i in intervals]


def parse_constraint_range(text):
    """GitHub style '>= 1.0.0, < 1.2.3' / '< 4.17.21' / '= 2.0.0' -> interval (or None)."""
    iv = {}
    for part in (text or "").split(","):
        m = re.match(r"^\s*(>=|<=|>|<|==|=)\s*(\S+)\s*$", part)
        if not m:
            return None
        op, ver = m.groups()
        if op == ">=":
            iv["introduced"] = ver
        elif op == ">":
            iv["introduced"], iv["introduced_exclusive"] = ver, True
        elif op == "<":
            iv["fixed"] = ver
        elif op == "<=":
            iv["last_affected"] = ver
        else:
            iv["introduced"] = iv["last_affected"] = ver
    return finish_range(iv) if iv else None
