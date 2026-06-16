#!/usr/bin/env python3
"""Discover Juliet testcases and write a manifest JSONL."""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.juliet.discovery import run_discovery


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of testcases to process.")
    parser.add_argument("--output", help="Manifest output path. Defaults to juliet.manifest_path in config.")
    parser.add_argument("--dry-run", action="store_true", help="Discover and report records without writing JSONL.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("discover_juliet started")
    result = run_discovery(
        args.config,
        cli_cwes=args.cwe,
        limit=args.limit,
        output_path=args.output,
        dry_run=args.dry_run,
    )
    logging.info(
        "Discovery complete: total=%s build_candidates=%s errors=%s dry_run=%s output=%s",
        result.total_records,
        result.build_candidates,
        result.errors,
        result.dry_run,
        result.output_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
