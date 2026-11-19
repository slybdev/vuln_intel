"""Scan request validation and merging Trivy findings with internal advisories."""
from __future__ import annotations

import hashlib
import json
import re
import uuid

from vuln_intel import scan_store
from vuln_intel.scan_matching import component_matches_affected, matching_fixed_versions

_APP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMMIT = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def validate_scan_request(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("The request body must be a JSON object.")
    application_id = payload.get("application_id")
    commit_sha = payload.get("commit_sha")
    ref = payload.get("ref")
    event_id = payload.get("event_id")
    if not isinstance(application_id, str) or not _APP_ID.fullmatch(application_id):
        raise ValueError("application_id is required and must be a valid inventory ID.")
    if not isinstance(commit_sha, str) or not _COMMIT.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a full 40- or 64-character commit hash.")
    if not isinstance(ref, str) or not ref.strip() or len(ref) > 255 or any(ord(char) < 32 for char in ref):
        raise ValueError("ref is required and must be a valid branch or tag reference.")
    if (not isinstance(event_id, str) or not event_id.strip() or len(event_id) > 200
            or any(ord(char) < 32 for char in event_id)):
        raise ValueError("event_id is required for idempotent scan requests.")
    idempotency_key = hashlib.sha256(f"{application_id}\0{event_id.strip()}".encode("utf-8")).hexdigest()
    return {
        "application_id": application_id,
        "commit_sha": commit_sha.lower(),
        "ref": ref.strip(),
        "idempotency_key": idempotency_key,
    }


def request_scan(payload: dict, actor="ci"):
    request = validate_scan_request(payload)
    return scan_store.enqueue_scan(**request, actor=actor)


def request_latest_scan(application_id: str, actor="local_operator"):
    if not isinstance(application_id, str):
        raise TypeError("application_id must be a string.")
    if not _APP_ID.fullmatch(application_id):
        raise ValueError("application_id must be a valid application ID.")
    event_id = f"manual-{uuid.uuid4().hex}"
    idempotency_key = hashlib.sha256(f"{application_id}\0{event_id}".encode("utf-8")).hexdigest()
    return scan_store.enqueue_scan(
        application_id, "HEAD", "HEAD", idempotency_key, actor=actor
    )


def request_inventory_initial_scan(application_id: str, external_inventory_id: str):
    if not isinstance(external_inventory_id, str) or not external_inventory_id:
        raise ValueError("external_inventory_id is required.")
    if not _APP_ID.fullmatch(application_id):
        raise ValueError("application_id must be a valid application ID.")
    idempotency_key = hashlib.sha256(
        f"inventory-initial-scan\0{external_inventory_id}".encode("utf-8")
    ).hexdigest()
    return scan_store.enqueue_scan(
        application_id, "HEAD", "HEAD", idempotency_key, actor="external_inventory"
    )


def _severity(*values):
    normalized = [(value or "UNKNOWN").upper() for value in values]
    return max(normalized, key=lambda value: _SEVERITY_RANK.get(value, 0), default="UNKNOWN")


def _evidence_list(evidence):
    if not evidence:
        return []
    return evidence if isinstance(evidence, list) else [evidence]


def combine_findings(components: list[dict], trivy_findings: list[dict]):
    """Union Trivy's report and internal feed matches without losing provenance."""
    component_by_key = {component["component_key"]: component for component in components}
    findings = {}
    evaluations = {}
    canonical_cache = {}
    candidates_cache = {}

    def canonical_id(identifier):
        if identifier not in canonical_cache:
            canonical_cache[identifier] = scan_store.resolve_identifier(identifier)
        return canonical_cache[identifier]

    def merge_finding(component, vulnerability_id, canonical, source, severity="UNKNOWN", evidence=None,
                      fixed_version=None):
        key_id = canonical or vulnerability_id.upper()
        key = (component["component_key"], key_id)
        item = findings.setdefault(key, {
            "component_key": component["component_key"],
            "canonical_id": canonical,
            "vulnerability_id": canonical or vulnerability_id,
            "fixed_version": None,
            "severity": "UNKNOWN",
            "sources": [],
            "evidence": {"trivy": [], "vuln_intel": []},
        })
        if source not in item["sources"]:
            item["sources"].append(source)
        item["severity"] = _severity(item["severity"], severity)
        item["fixed_version"] = item["fixed_version"] or fixed_version
        if evidence is not None:
            bucket = item["evidence"][source]
            encoded = json.dumps(evidence, sort_keys=True, default=str)
            if all(json.dumps(existing, sort_keys=True, default=str) != encoded for existing in bucket):
                bucket.append(evidence)

    for raw in trivy_findings:
        component = component_by_key.get(raw["component_key"])
        if not component:
            continue
        identifier = raw["vulnerability_id"]
        merge_finding(component, identifier, canonical_id(identifier), "trivy",
                      raw.get("severity"), raw.get("evidence"), raw.get("fixed_version"))

    for component in components:
        lookup_key = (component["ecosystem"], component["package_name"])
        if lookup_key not in candidates_cache:
            candidates_cache[lookup_key] = scan_store.get_candidate_vulnerabilities(*lookup_key)
        for canonical, vulnerability in candidates_cache[lookup_key]:
            matched_entries, unknown_entries = [], []
            for affected in vulnerability.get("affected") or []:
                result = component_matches_affected(component, affected)
                if result is True:
                    matched_entries.append(affected)
                elif result is None:
                    unknown_entries.append(affected)
            if matched_entries:
                ids = vulnerability.get("ids") or [canonical]
                identifier = canonical or ids[0]
                fixed = next(
                    (version for entry in matched_entries for version in matching_fixed_versions(component, entry)),
                    None,
                )
                fixed = fixed or next((version for entry in matched_entries for version in entry.get("patched") or []), None)
                merge_finding(component, identifier, canonical, "vuln_intel",
                              vulnerability.get("severity"), {
                                  "advisory": vulnerability,
                                  "matched_affected": matched_entries,
                              }, fixed)
            elif unknown_entries:
                evaluations[(component["component_key"], canonical)] = {
                    "component_key": component["component_key"],
                    "canonical_id": canonical,
                    "reason": "Matching advisory data exists, but its package identity or version range could not be evaluated safely.",
                    "evidence": {
                        "installed_version": component["version"],
                        "affected": unknown_entries,
                    },
                }

    return list(findings.values()), list(evaluations.values())
