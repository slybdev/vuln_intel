#!/usr/bin/env python3
"""Run the whole vulnerability intelligence pipeline with one command.

    python main.py

What happens, in order:
  1. PULL     latest changes from NVD, OSV, GitHub Security Advisories, CISA KEV and EPSS
              -> saved untouched in vuln_data/raw/<run_id>/
  2. CLEAN    validate every record, map it to one schema, merge duplicates across sources,
              standardize ecosystems and version ranges
  3. STORE    update PostgreSQL (or the legacy JSON store) and write a text report

Optional flags are passed straight through, e.g.:
    python main.py --sources nvd,kev
    python main.py --since 2026-11-01T00:00:00Z
    python main.py --phase process
Exit code: 0 = everything succeeded, 1 = at least one source failed, 2 = unsupported Python.
"""
import logging
import sys

if sys.version_info < (3, 9):  # checked before importing the package, which needs 3.9+
    sys.exit("vuln-intel needs Python 3.9 or newer (found %d.%d)." % sys.version_info[:2])

from vuln_intel import config  # noqa: E402
from vuln_intel.cli import main as run_cli  # noqa: E402


def _preflight() -> None:
    print("=" * 72)
    print("VULNERABILITY INTELLIGENCE PIPELINE")
    print("=" * 72)
    print(f"Data directory : {config.DATA_DIR.resolve()}")
    print(f"OSV ecosystems : {', '.join(config.OSV_ECOSYSTEMS)}")
    print(f"NVD API key    : {'set' if config.NVD_API_KEY else 'NOT set (works, but NVD will throttle you; see docs)'}")
    print(f"GitHub token   : {'set' if config.GITHUB_TOKEN else 'NOT set (works, lower rate limit)'}")
    print("-" * 72)


def _existing_reports() -> set:
    return {p.name for p in (config.DATA_DIR / "reports").glob("report_*.txt")}


def main(argv=None) -> int:
    _preflight()
    before = _existing_reports()
    root_logger = logging.getLogger()
    existing_handlers = set(root_logger.handlers)
    try:
        code = run_cli(argv)
    finally:
        for handler in root_logger.handlers[:]:
            if handler not in existing_handlers:
                root_logger.removeHandler(handler)
                handler.close()

    new_reports = sorted(_existing_reports() - before)
    print("\n" + "=" * 72)
    if new_reports:
        print((config.DATA_DIR / "reports" / new_reports[-1]).read_text(encoding="utf-8"))
    print("Database   :", "PostgreSQL" if config.DATABASE_URL else config.DB_PATH.resolve())
    print("Raw data   :", (config.DATA_DIR / "raw").resolve())
    print("Rejected   :", (config.DATA_DIR / "rejected").resolve(), "(only exists if something failed validation)")
    print("Logs       :", (config.DATA_DIR / "logs" / "pipeline.log").resolve())
    if code:
        print("\nRESULT: finished WITH ERRORS - at least one source failed. See the log; the next run retries it.")
    else:
        print("\nRESULT: success")
    return code


if __name__ == "__main__":
    sys.exit(main())
