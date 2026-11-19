"""Central configuration: environment variables, source URLs and filesystem layout.

Other modules read values as ``config.NAME`` (not ``from config import NAME``) so tests
and callers can change them at runtime, e.g. ``config.set_data_dir(tmp_path)``.
"""
from __future__ import annotations

import os
import re
from pathlib import Path


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _load_dotenv(path=None):
    env_path = path or Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return
    for line_number, raw_line in enumerate(env_path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not _ENV_NAME.fullmatch(name):
            raise ValueError(f"{env_path}:{line_number}: expected a valid NAME=VALUE entry.")
        if name not in os.environ:
            os.environ[name] = value.strip()


def _csv_env(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


_load_dotenv()

# --- source and application credentials ------------------------------------------------
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
DATABASE_URL = os.getenv("VULN_DATABASE_URL", "")
SCAN_API_TOKEN = os.getenv("VULN_SCAN_API_TOKEN", "")
INVENTORY_API_TOKEN = os.getenv("VULN_INVENTORY_API_TOKEN", "")
PUBLIC_API_BASE_URL = os.getenv("VULN_PUBLIC_API_BASE_URL", "").rstrip("/")
REPOSITORY_ENCRYPTION_KEY = os.getenv("VULN_REPOSITORY_ENCRYPTION_KEY", "")
REPOSITORY_HOSTS = _csv_env("VULN_REPOSITORY_HOSTS", "github.com,gitlab.com")
INVENTORY_CALLBACK_HOSTS = _csv_env("VULN_INVENTORY_CALLBACK_HOSTS", "")
TRIVY_BINARY = os.getenv("TRIVY_BINARY", "trivy")
TRIVY_VERSION = os.getenv("TRIVY_VERSION", "0.76.2")
TRIVY_TIMEOUT_SECONDS = int(os.getenv("TRIVY_TIMEOUT_SECONDS", "1800"))
SCAN_WORKER_POLL_SECONDS = int(os.getenv("SCAN_WORKER_POLL_SECONDS", "5"))
SCAN_MAX_ATTEMPTS = int(os.getenv("SCAN_MAX_ATTEMPTS", "3"))

# --- collection behaviour ---------------------------------------------------------------
OSV_ECOSYSTEMS = _csv_env("OSV_ECOSYSTEMS", "PyPI,npm,Go,Maven,crates.io,NuGet,RubyGems,Packagist")
GHSA_TYPES = _csv_env("GHSA_TYPES", "reviewed")  # any of: reviewed, unreviewed, malware
FIRST_RUN_LOOKBACK_HOURS = int(os.getenv("FIRST_RUN_LOOKBACK_HOURS", "24"))
OVERLAP_HOURS = int(os.getenv("OVERLAP_HOURS", "6"))  # re-pull this much before the watermark

# --- source endpoints -------------------------------------------------------------------
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
GHSA_URL = "https://api.github.com/advisories"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"  # formerly epss.cyentia.com

# --- filesystem layout (derived from the data directory) --------------------------------
DATA_DIR: Path
DB_PATH: Path
STATE_PATH: Path
CONTRIB_PATH: Path
SCAN_ARTIFACTS_DIR: Path


def set_data_dir(path: str | Path) -> None:
    """Point every output path at `path`. Called once at import with VULN_DATA_DIR / ./vuln_data."""
    global DATA_DIR, DB_PATH, STATE_PATH, CONTRIB_PATH, SCAN_ARTIFACTS_DIR
    DATA_DIR = Path(path)
    DB_PATH = DATA_DIR / "standardized_vulnerabilities.json"
    STATE_PATH = DATA_DIR / "state" / "state.json"
    CONTRIB_PATH = DATA_DIR / "state" / "contributions.json"
    SCAN_ARTIFACTS_DIR = Path(os.getenv("VULN_SCAN_ARTIFACTS_DIR", str(DATA_DIR / "scans")))


set_data_dir(os.getenv("VULN_DATA_DIR", "vuln_data"))
