"""Ecosystem name and package name standardization."""
from __future__ import annotations




import re


ECOSYSTEM_MAP = {
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI", "npm": "npm", "node": "npm", "go": "Go", "golang": "Go",
    "maven": "Maven", "crates.io": "crates.io", "rust": "crates.io", "cargo": "crates.io",
    "nuget": "NuGet", ".net": "NuGet", "rubygems": "RubyGems", "gem": "RubyGems", "ruby": "RubyGems",
    "packagist": "Packagist", "composer": "Packagist", "php": "Packagist", "pub": "Pub", "hex": "Hex",
    "erlang": "Hex", "swift": "SwiftURL", "actions": "GitHub Actions", "github actions": "GitHub Actions",
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "cpe": "cpe",
}


VERSION_SCHEME = {"PyPI": "pep440", "npm": "semver", "Go": "semver", "crates.io": "semver", "Maven": "maven",
                  "NuGet": "nuget", "RubyGems": "rubygems", "Packagist": "composer", "Debian": "dpkg",
                  "Ubuntu": "dpkg", "Alpine": "apk", "Hex": "semver", "Pub": "semver", "cpe": "generic"}


LOWERCASE_ECOSYSTEMS = {"npm", "NuGet", "RubyGems", "crates.io", "Packagist"}


def std_ecosystem(name):
    """'pip'/'PyPI' -> 'PyPI'; 'Debian:12' -> ('Debian', '12')."""
    base, _, release = (name or "").partition(":")
    return ECOSYSTEM_MAP.get(base.strip().lower(), base.strip() or "unknown"), (release or None)


def std_package(eco, name):
    name = (name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503
    return name.lower() if eco in LOWERCASE_ECOSYSTEMS else name
