"""CVSS helpers: v3.x base score calculator, severity labels, entry builder."""
from __future__ import annotations

import math
import re


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        if impact <= 0:
            return 0.0
        expl = 8.22 * av * ac * pr * ui
        return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, AttributeError):
        return None


def severity_label(score):
    if score is None:
        return None
    return "NONE" if score == 0 else "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def vector_version(vector):
    m = re.match(r"^CVSS:(\d\.\d)/", vector or "")
    return m.group(1) if m else ("2.0" if vector and "AV:" in vector else None)


def make_cvss(version, vector, score, severity, provider):
    version = str(version) if version else vector_version(vector)
    if score is None and version in ("3.0", "3.1") and vector:
        score = cvss3_score(vector)
    sev = (severity or severity_label(score) or "").upper() or None
    return {"version": version, "vector": vector, "score": score,
            "severity": "MEDIUM" if sev == "MODERATE" else sev, "provider": provider}
