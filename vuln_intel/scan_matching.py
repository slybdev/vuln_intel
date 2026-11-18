"""Trivy report parsing and internal affected-version matching."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qs, unquote

from packaging.version import InvalidVersion, Version
from semantic_version import Version as SemVer

from vuln_intel.normalization.ecosystems import std_ecosystem, std_package


_PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
    "deb": "Debian",
    "apk": "Alpine",
}


def parse_purl(purl: str | None) -> dict:
    """Extract the package identity/version needed to match a package URL."""
    if not purl or not purl.startswith("pkg:"):
        return {}
    body = purl[4:].split("#", 1)[0]
    path_and_version, _, query = body.partition("?")
    package_type, separator, path = path_and_version.partition("/")
    if not separator or package_type not in _PURL_ECOSYSTEMS:
        return {}
    path, at, version = path_and_version[len(package_type) + 1:].rpartition("@")
    if not at:
        path = path_and_version[len(package_type) + 1:]
        version = ""
    package_type = package_type.lower()
    path = unquote(path).strip("/")
    if not path:
        return {}
    if package_type == "maven":
        group, slash, artifact = path.rpartition("/")
        name = f"{group}:{artifact}" if slash else path
    elif package_type in {"deb", "apk"} and "/" in path:
        _, name = path.split("/", 1)
    elif package_type == "npm" and path.startswith("@") and "/" in path:
        name = path
    else:
        name = path
    ecosystem, release = std_ecosystem(_PURL_ECOSYSTEMS[package_type])
    if package_type in {"deb", "apk"}:
        qualifiers = parse_qs(query, keep_blank_values=True)
        distro = (qualifiers.get("distro") or [""])[0]
        match = re.search(r"(?:debian|ubuntu|alpine)[-/]?([0-9][A-Za-z0-9.]*)", distro, re.IGNORECASE)
        release = match.group(1) if match else None
    return {
        "purl": purl,
        "ecosystem": ecosystem,
        "release": release,
        "package_name": std_package(ecosystem, name),
        "version": unquote(version),
    }


def normalize_component(record: dict, target: str = "") -> dict | None:
    purl = record.get("purl")
    identity = parse_purl(purl)
    if not identity:
        raw_ecosystem = record.get("ecosystem") or record.get("PkgType") or record.get("Type") or "unknown"
        ecosystem, release = std_ecosystem(raw_ecosystem)
        package_name = record.get("name") or record.get("PkgName") or ""
        version = record.get("version") or record.get("InstalledVersion") or ""
        identity = {
            "purl": purl,
            "ecosystem": ecosystem,
            "release": release,
            "package_name": std_package(ecosystem, package_name),
            "version": version,
        }
    if not identity.get("version"):
        identity["version"] = record.get("version") or record.get("InstalledVersion") or ""
    if not identity.get("package_name"):
        identity["package_name"] = std_package(identity["ecosystem"], record.get("name") or record.get("PkgName") or "")
    if not identity["package_name"] or not identity["version"]:
        return None
    identity["target"] = target or record.get("target") or ""
    identity["properties"] = record.get("properties") or {}
    identity["component_key"] = component_key(identity)
    return identity


def component_key(component: dict) -> str:
    identity = "\0".join(str(component.get(key) or "") for key in (
        "purl", "ecosystem", "release", "package_name", "version",
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def merge_components(components: list[dict]) -> list[dict]:
    def properties_map(value):
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, list):
            return {"cyclonedx_properties": value}
        return {}

    merged = {}
    for component in components:
        key = component["component_key"]
        component_properties = properties_map(component.get("properties"))
        if key not in merged:
            component["properties"] = component_properties
            merged[key] = component
            continue
        current = merged[key]
        current_properties = properties_map(current.get("properties"))
        targets = set(current_properties.get("targets", []))
        targets.update(component_properties.get("targets", []))
        targets.update(target for target in (current.get("target"), component.get("target")) if target)
        properties = {**current_properties, **component_properties}
        if targets:
            properties["targets"] = sorted(targets)
        current["target"] = ", ".join(sorted(targets))
        current["properties"] = properties
    return list(merged.values())


def parse_cyclonedx(document: dict) -> list[dict]:
    components = []
    stack = list(document.get("components") or [])
    while stack:
        record = stack.pop()
        if not isinstance(record, dict):
            continue
        stack.extend(record.get("components") or [])
        component = normalize_component(record)
        if component:
            components.append(component)
    return merge_components(components)


def parse_trivy_report(document: dict) -> tuple[list[dict], list[dict]]:
    """Return unique components and raw Trivy vulnerability findings."""
    components, findings = [], []
    for result in document.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target") or ""
        for vulnerability in result.get("Vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            package_id = vulnerability.get("PkgIdentifier") or {}
            purl = package_id.get("PURL") if isinstance(package_id, dict) else None
            component = normalize_component({
                "purl": purl,
                "name": vulnerability.get("PkgName"),
                "version": vulnerability.get("InstalledVersion"),
                "ecosystem": result.get("Type") or "unknown",
                "PkgType": result.get("Type") or "unknown",
            }, target)
            if not component:
                continue
            components.append(component)
            vulnerability_id = (vulnerability.get("VulnerabilityID") or "").strip()
            if not vulnerability_id:
                continue
            findings.append({
                "component_key": component["component_key"],
                "vulnerability_id": vulnerability_id,
                "fixed_version": vulnerability.get("FixedVersion") or None,
                "severity": (vulnerability.get("Severity") or "UNKNOWN").upper(),
                "source": "trivy",
                "evidence": vulnerability,
            })
    return merge_components(components), findings


def _parse_version(value: str, scheme: str):
    if scheme == "pep440":
        return Version(value)
    if scheme == "semver":
        return SemVer.coerce(value[1:] if value.startswith("v") else value)
    raise InvalidVersion(f"Unsupported version scheme: {scheme}")


def _same_version(left: str, right: str, scheme: str) -> bool | None:
    try:
        return _parse_version(left, scheme) == _parse_version(right, scheme)
    except (InvalidVersion, ValueError, TypeError):
        return None


def _range_matches(version: str, interval: dict, scheme: str) -> bool | None:
    try:
        current = _parse_version(version, scheme)
        introduced = interval.get("introduced")
        if introduced and introduced != "0":
            lower = _parse_version(introduced, scheme)
            if current < lower or (interval.get("introduced_exclusive") and current == lower):
                return False
        fixed = interval.get("fixed")
        if fixed and current >= _parse_version(fixed, scheme):
            return False
        last_affected = interval.get("last_affected")
        if last_affected and current > _parse_version(last_affected, scheme):
            return False
        return True
    except (InvalidVersion, ValueError, TypeError):
        return None


def version_is_affected(installed_version: str, affected: dict) -> bool | None:
    """Return true/false when comparable, or None when the range is not safely evaluable."""
    scheme = affected.get("scheme")
    versions = affected.get("versions") or []
    if scheme not in {"pep440", "semver"}:
        return True if installed_version in versions else None
    if versions:
        comparisons = [_same_version(installed_version, item, scheme) for item in versions]
        if any(result is True for result in comparisons):
            return True
        if not affected.get("ranges"):
            return False if all(result is not None for result in comparisons) else None
    ranges = affected.get("ranges") or []
    if not ranges:
        return None
    results = [_range_matches(installed_version, item, scheme) for item in ranges]
    if any(result is True for result in results):
        return True
    if all(result is not None for result in results):
        return False
    return None


def component_matches_affected(component: dict, affected: dict) -> bool | None:
    ecosystem, parsed_release = std_ecosystem(affected.get("ecosystem") or "")
    release = affected.get("release") or parsed_release
    if ecosystem != component.get("ecosystem"):
        return False
    if release:
        if not component.get("release"):
            return None
        if release != component["release"]:
            return False
    expected_package = std_package(ecosystem, affected.get("package") or "")
    if expected_package != component.get("package_name"):
        return False
    return version_is_affected(component["version"], affected)


