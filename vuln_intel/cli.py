"""Command line interface."""
from __future__ import annotations

import argparse
import logging

from vuln_intel import config
from vuln_intel.collectors import ORDER
from vuln_intel.pipeline import run_collect, run_process
from vuln_intel.utils import parse_ts


def main(argv=None):
    ap = argparse.ArgumentParser(description="Vulnerability intelligence collection + normalization")
    ap.add_argument("--phase", choices=["all", "collect", "process"], default="all")
    ap.add_argument("--sources", default=",".join(ORDER), help="comma list of: " + ",".join(ORDER))
    ap.add_argument("--since", help="ISO timestamp overriding the collection window start")
    args = ap.parse_args(argv)

    (config.DATA_DIR / "logs").mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(config.DATA_DIR / "logs" / "pipeline.log")])
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    unknown = sources - set(ORDER)
    if unknown:
        ap.error(f"unknown sources: {', '.join(sorted(unknown))}")
    since = parse_ts(args.since) if args.since else None
    if args.since and not since:
        ap.error("--since must be an ISO timestamp such as 2026-11-01T00:00:00Z")

    failed = False
    if args.phase in ("all", "collect"):
        _, failed = run_collect(sources, since)
    if args.phase in ("all", "process"):
        run_process()
    return 1 if failed else 0
