#!/usr/bin/env python3
"""Build Juliet testcase binaries from the manifest."""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.juliet.builder import run_build


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of testcases to process.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned compile commands without running them.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing successful outputs.")
    parser.add_argument("--force", action="store_true", help="Rebuild outputs even if they exist.")
    parser.add_argument("--jobs", type=int, help="Number of worker jobs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("build_juliet started")
    summary = run_build(
        args.config,
        cli_cwes=args.cwe,
        limit=args.limit,
        dry_run=args.dry_run,
        resume=args.resume if args.resume else None,
        force=args.force if args.force else None,
        jobs=args.jobs,
    )
    logging.info(
        "Build summary: planned=%s attempted=%s succeeded=%s failed=%s skipped=%s dry_run=%s metadata=%s status=%s",
        summary.planned,
        summary.attempted,
        summary.succeeded,
        summary.failed,
        summary.skipped,
        summary.dry_run,
        summary.metadata_path,
        summary.status_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
