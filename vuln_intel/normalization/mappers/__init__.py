"""Per-source field mappers. Each takes one raw record and returns a normalized view."""
from __future__ import annotations

from vuln_intel.normalization.mappers.epss import normalize_epss
from vuln_intel.normalization.mappers.ghsa import normalize_ghsa
from vuln_intel.normalization.mappers.kev import normalize_kev
from vuln_intel.normalization.mappers.nvd import normalize_nvd
from vuln_intel.normalization.mappers.osv import normalize_osv

NORMALIZERS = {"nvd": normalize_nvd, "osv": normalize_osv, "ghsa": normalize_ghsa,
               "kev": normalize_kev, "epss": normalize_epss}
