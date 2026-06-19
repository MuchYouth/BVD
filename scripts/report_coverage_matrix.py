#!/usr/bin/env python3
"""DEPRECATED experimental report for old P-code-native CWE rule coverage."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.analysis.rule_registry import RuleRegistry
from src.juliet.discovery import load_config, normalize_cwe, resolve_cwe_scope

LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of CWE rows to output.")
    parser.add_argument("--resume", action="store_true", help="Accepted for CLI consistency.")
    parser.add_argument("--force", action="store_true", help="Accepted for CLI consistency.")
    parser.add_argument("--jobs", type=int, help="Accepted for CLI consistency.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    rows = run_report(args.config, cli_cwes=args.cwe, limit=args.limit)
    logging.info("Wrote %s CWE support rows to reports/cwe_support_matrix.md", len(rows))
    return 0


def run_report(
    config_path: str | Path,
    *,
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    config = load_config(config_path)
    cwe_scope = resolve_cwe_scope(config, cli_cwes) if cli_cwes else None
    rows = build_rows(config, cwe_scope=cwe_scope)
    if limit is not None:
        rows = rows[:limit]
    output_path = Path("reports/cwe_support_matrix.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(rows), encoding="utf-8")
    return rows


def build_rows(config: dict[str, Any], *, cwe_scope: set[str] | None) -> list[dict[str, Any]]:
    juliet_config = config.get("juliet", {})
    dataset_config = config.get("dataset", {})
    analysis_config = config.get("analysis", {})
    manifest_path = Path(juliet_config.get("manifest_path", "data/manifests/juliet_manifest.jsonl"))
    build_metadata_path = Path(dataset_config.get("binaries_dir", "data/binaries")) / "build_metadata.jsonl"

    manifest_records = read_jsonl(manifest_path)
    build_records = read_jsonl(build_metadata_path)
    registry = RuleRegistry(analysis_config.get("rule_dir", "configs/cwe_rules"))

    discovered = Counter(str(record.get("cwe", "")) for record in manifest_records if record.get("build_candidate") is True)
    build_attempted = Counter(str(record.get("cwe", "")) for record in build_records)
    build_success = Counter(str(record.get("cwe", "")) for record in build_records if record.get("compile_success") is True)
    configured = set(registry.rules)
    target_cwes = configured | set(discovered) | selected_config_cwes(juliet_config)
    target_cwes.discard("")
    if cwe_scope is not None:
        target_cwes = {cwe for cwe in target_cwes if cwe in cwe_scope}

    rows = []
    for cwe in sorted(target_cwes, key=cwe_sort_key):
        rule = registry.get_rule(cwe)
        rows.append(
            {
                "CWE": cwe,
                "discovered_testcases": discovered.get(cwe, 0),
                "build_attempted": build_attempted.get(cwe, 0),
                "build_success": build_success.get(cwe, 0),
                "rule_status": rule.status,
                "source_rule_defined": bool(rule.sources),
                "sink_rule_defined": bool(rule.sinks),
                "trace_rule_defined": bool(rule.trace),
                "requires_call_arguments": requires_call_arguments(rule.raw),
                "requires_memory_model": bool(rule.requires.get("memory_model", False)),
                "requires_interprocedural_analysis": bool(rule.requires.get("interprocedural_analysis", False)),
                "supported_now": rule.status == "supported",
                "notes": rule.notes,
            }
        )
    return rows


def render_markdown(rows: list[dict[str, Any]]) -> str:
    headers = [
        "CWE",
        "discovered_testcases",
        "build_attempted",
        "build_success",
        "rule_status",
        "source_rule_defined",
        "sink_rule_defined",
        "trace_rule_defined",
        "requires_call_arguments",
        "requires_memory_model",
        "requires_interprocedural_analysis",
        "supported_now",
        "notes",
    ]
    lines = ["# CWE Support Matrix", "", "| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(format_cell(row.get(header, "")) for header in headers) + " |")
    return "\n".join(lines) + "\n"


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    jsonl_path = Path(path)
    if not jsonl_path.exists():
        return []
    records: list[dict[str, Any]] = []
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def selected_config_cwes(juliet_config: dict[str, Any]) -> set[str]:
    cwes: set[str] = set()
    for key in ("target_cwes", "active_cwes"):
        selected = juliet_config.get(key, {}).get("selected", [])
        for value in selected:
            cwe = normalize_cwe(str(value))
            if cwe:
                cwes.add(cwe)
    return cwes


def requires_call_arguments(raw_rule: dict[str, Any]) -> bool:
    sinks = raw_rule.get("sinks", {}) if isinstance(raw_rule, dict) else {}
    trace = raw_rule.get("trace", {}) if isinstance(raw_rule, dict) else {}
    if not isinstance(sinks, dict):
        return False
    return bool(
        sinks.get("argument_indices")
        or sinks.get("argument_policy")
        or sinks.get("format_functions")
        or str(trace.get("type", "")).endswith("_argument")
    )


def cwe_sort_key(cwe: str) -> tuple[int, str]:
    normalized = normalize_cwe(cwe)
    if normalized:
        return (int(normalized.replace("CWE", "")), cwe)
    return (10**9, cwe)


def format_cell(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())
