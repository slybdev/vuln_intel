"""Duplicate detection and entity resolution (alias graph + merge store)."""
from __future__ import annotations

import json

from vuln_intel.normalization.merge import merge_views
from vuln_intel.utils import CVE_RE, iso, stable_hash


def expand_views(v):
    """A record bundling several CVEs (e.g. a distro advisory) must not glue those CVEs into one entity,
    so it is fanned out into one view per CVE."""
    cves = sorted({i for i in v["ids"] if CVE_RE.fullmatch(i)})
    if len(cves) <= 1 or v["kind"] != "advisory" or v["source"] == "nvd":
        v["key"] = f'{v["source"]}:{v["source_id"]}'
        return [v]
    out = []
    for c in cves:
        d = json.loads(json.dumps(v))
        d["ids"], d["key"] = [c], f'{v["source"]}:{v["source_id"]}#{c}'
        out.append(d)
    return out


def pick_canonical(ids):
    cves = sorted(i for i in ids if CVE_RE.fullmatch(i))
    if cves:
        return cves[0]
    ghsas = sorted(i for i in ids if i.upper().startswith("GHSA-"))
    return ghsas[0] if ghsas else sorted(ids)[0]


class Store:
    """Entity resolution: records sharing any identifier (CVE / GHSA / OSV id / alias) become one entity.
    Each source's latest contribution is kept so an update replaces that source's old data cleanly."""

    def __init__(self, db, contribs, now):
        self.ents, self.contribs, self.now = db["vulnerabilities"], contribs, now
        self.index, self.member_of = {}, {}
        for e in self.ents.values():
            for i in e["ids"]:
                self.index[i] = e
            for k in e["members"]:
                self.member_of[k] = e
        self.dirty, self.new_objs = {}, set()
        self.stats = {"added": 0, "updated": 0, "unchanged": 0, "stale": 0}
        self.new_ids, self.changed_ids = [], []

    def upsert(self, view):
        key = view["key"]
        view.pop("_hash", None)
        view["_hash"] = stable_hash(view)
        old = self.contribs.get(key)
        if old and old.get("_hash") == view["_hash"]:
            self.stats["unchanged"] += 1
            return
        if old and view["kind"] == "advisory" and old.get("modified") and view["modified"] < old["modified"]:
            self.stats["stale"] += 1  # overlap window re-delivered an older version
            return
        if old and view.get("epss") and old.get("epss") and (view["epss"]["date"] or "") < (old["epss"]["date"] or ""):
            self.stats["stale"] += 1
            return
        hits = {id(self.index[i]): self.index[i] for i in view["ids"] if i in self.index}
        if key in self.member_of:
            hits[id(self.member_of[key])] = self.member_of[key]
        if not hits:
            target = {"id": pick_canonical(view["ids"]), "ids": [], "members": [], "first_seen": iso(self.now)}
            self.ents[target["id"]] = target
            self.new_objs.add(id(target))
        else:
            target, *others = hits.values()
            for other in others:  # this record bridges two entities -> merge them
                target["ids"] = sorted(set(target["ids"]) | set(other["ids"]))
                target["members"] = sorted(set(target["members"]) | set(other["members"]))
                target["first_seen"] = min(target["first_seen"], other["first_seen"])
                for k in other["members"]:
                    self.member_of[k] = target
                for i in other["ids"]:
                    self.index[i] = target
                other["_dead"] = True
                self.dirty.pop(id(other), None)
                self.new_objs.discard(id(other))
                if self.ents.get(other["id"]) is other:
                    del self.ents[other["id"]]
        target["ids"] = sorted(set(target["ids"]) | set(view["ids"]))
        target["members"] = sorted(set(target["members"]) | {key})
        for i in target["ids"]:
            self.index[i] = target
        self.member_of[key] = target
        self.contribs[key] = view
        self.dirty[id(target)] = target
        self.stats["updated" if old else "added"] += 1

    def finalize(self):
        for e in list(self.dirty.values()):
            if e.get("_dead"):
                continue
            views = [self.contribs[k] for k in e["members"] if k in self.contribs]
            merged = merge_views(views)
            canon = pick_canonical(e["ids"])
            if self.ents.get(e["id"]) is e and e["id"] != canon:
                del self.ents[e["id"]]
            e["id"] = canon
            self.ents[canon] = e
            e["sources"] = sorted({v["source"] for v in views})
            e["source_ids"] = sorted({f'{v["source"]}:{v["source_id"]}' for v in views})
            digest = stable_hash({"ids": e["ids"], **merged})
            changed = digest != e.get("content_hash")
            e.update(merged)
            e["content_hash"], e["last_seen"] = digest, iso(self.now)
            if changed:
                e["last_changed"] = iso(self.now)
                (self.new_ids if id(e) in self.new_objs else self.changed_ids).append(canon)
        self.dirty.clear()
        self.new_objs.clear()
