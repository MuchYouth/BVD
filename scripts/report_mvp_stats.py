#!/usr/bin/env python3
"""Report MVP pipeline statistics."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.dataset.leakage_check import check_model_input
from src.juliet.discovery import load_config, resolve_cwe_scope

LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of records to inspect.")
    parser.add_argument("--resume", action="store_true", help="Reuse cached report inputs where applicable.")
    parser.add_argument("--force", action="store_true", help="Regenerate report outputs even if they exist.")
    parser.add_argument("--jobs", type=int, help="Number of worker jobs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    summary = run_report(args.config, cli_cwes=args.cwe, limit=args.limit)
    for key, value in summary.items():
        logging.info("%s=%s", key, value)
    return 0


def run_report(
    config_path: str | Path,
    *,
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    config = load_config(config_path)
    cwe_scope = resolve_cwe_scope(config, cli_cwes)
    summary = collect_summary(config, cwe_scope=cwe_scope, limit=limit)
    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "mvp_stats.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (report_dir / "mvp_stats.md").write_text(render_markdown(summary), encoding="utf-8")
    return summary


def collect_summary(config: dict[str, Any], *, cwe_scope: set[str] | None, limit: int | None = None) -> dict[str, Any]:
    juliet_config = config.get("juliet", {})
    dataset_config = config.get("dataset", {})
    ghidra_config = config.get("ghidra", {})

    manifest_path = Path(juliet_config.get("manifest_path", "data/manifests/juliet_manifest.jsonl"))
    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    build_metadata_path = binaries_dir / "build_metadata.jsonl"
    pcode_dir = Path(ghidra_config.get("output_dir", dataset_config.get("pcode_dir", "data/pcode")))
    traces_dir = Path(dataset_config.get("traces_dir", "data/traces"))
    output_dir = Path(dataset_config.get("output_dir", "data/datasets"))

    manifest_records = apply_limit(filter_by_cwe(read_jsonl(manifest_path), cwe_scope), limit)
    build_records = apply_limit(filter_by_cwe(read_jsonl(build_metadata_path), cwe_scope), limit)
    trace_records = apply_limit(read_trace_records(traces_dir, cwe_scope), limit)
    dataset_records = apply_limit(read_dataset_records(output_dir, cwe_scope), limit)
    pcode_records_by_file = read_records_by_file(pcode_dir, "*.pcode.jsonl", cwe_scope)
    callsite_records_by_file = read_records_by_file(pcode_dir, "*.callsites.jsonl", cwe_scope)
    ghidra_error_records = read_records_from_tree(pcode_dir, "*.ghidra_errors.jsonl", cwe_scope)

    build_summary = build_stats(build_records)
    ghidra_summary = ghidra_stats(pcode_records_by_file, callsite_records_by_file, ghidra_error_records)
    trace_summary = trace_stats(trace_records)
    leakage_summary = leakage_stats(dataset_records)
    sample_records = sample_trace_records(trace_records, limit=3)

    summary = {
        "total_testcases": sum(1 for record in manifest_records if record.get("build_candidate") is True),
        "build_attempted": len(build_records),
        "build_success": sum(1 for record in build_records if record.get("compile_success") is True),
        "build_failed": sum(1 for record in build_records if record.get("compile_success") is not True),
        "ghidra_attempted": max(count_files(pcode_dir, "*.pcode.jsonl", cwe_scope), count_files(pcode_dir, "*.callsites.jsonl", cwe_scope)),
        "ghidra_success": count_ghidra_successes(pcode_dir, cwe_scope),
        "ghidra_failed": count_ghidra_failures(pcode_dir, cwe_scope),
        "pcode_files": count_files(pcode_dir, "*.pcode.jsonl", cwe_scope),
        "callsite_files": count_files(pcode_dir, "*.callsites.jsonl", cwe_scope),
        "trace_files": count_files(traces_dir, "*.trace.jsonl", cwe_scope),
        "dataset_records": len(dataset_records),
        "path_found_count": sum(1 for record in trace_records if record.get("path_found") is True),
        "path_not_found_count": sum(1 for record in trace_records if record.get("path_found") is False),
        "path_unknown_count": sum(1 for record in trace_records if record.get("path_found") == "unknown"),
        "leakage_failed_count": sum(1 for record in dataset_records if record.get("leakage_check", {}).get("status") == "failed"),
        "build_summary": build_summary,
        "ghidra_summary": ghidra_summary,
        "trace_summary": trace_summary,
        "leakage_summary": leakage_summary,
        "sample_records": sample_records,
    }
    return summary


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


def filter_by_cwe(records: list[dict[str, Any]], cwe_scope: set[str] | None) -> list[dict[str, Any]]:
    if cwe_scope is None:
        return records
    return [record for record in records if str(record.get("cwe", "")) in cwe_scope]


def apply_limit(records: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    return records[:limit] if limit is not None else records


def read_dataset_records(output_dir: Path, cwe_scope: set[str] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in output_dir.glob("*.jsonl"):
        records.extend(filter_by_cwe(read_jsonl(path), cwe_scope))
    return records


def read_trace_records(traces_dir: Path, cwe_scope: set[str] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in traces_dir.rglob("*.trace.jsonl"):
        if cwe_scope is not None and not any(part in cwe_scope for part in path.parts):
            continue
        records.extend(read_jsonl(path))
    return records


def read_records_from_tree(root: Path, pattern: str, cwe_scope: set[str] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not root.exists():
        return records
    for path in root.rglob(pattern):
        if cwe_scope is not None and not any(part in cwe_scope for part in path.parts):
            continue
        records.extend(read_jsonl(path))
    return records


def read_records_by_file(root: Path, pattern: str, cwe_scope: set[str] | None) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {}
    if not root.exists():
        return records
    for path in root.rglob(pattern):
        if cwe_scope is not None and not any(part in cwe_scope for part in path.parts):
            continue
        records[str(path)] = read_jsonl(path)
    return records


def build_stats(build_records: list[dict[str, Any]]) -> dict[str, Any]:
    compilers = Counter(str(record.get("compiler", "")) for record in build_records if record.get("compiler"))
    opt_levels = Counter(str(record.get("opt_level", "")) for record in build_records if record.get("opt_level"))
    return {
        "attempted": len(build_records),
        "success": sum(1 for record in build_records if record.get("compile_success") is True),
        "failed": sum(1 for record in build_records if record.get("compile_success") is not True),
        "compiler": dict(compilers),
        "opt_level": dict(opt_levels),
    }


def ghidra_stats(
    pcode_records_by_file: dict[str, list[dict[str, Any]]],
    callsite_records_by_file: dict[str, list[dict[str, Any]]],
    error_records: list[dict[str, Any]],
) -> dict[str, Any]:
    function_counts = []
    pcode_ops_per_function = []
    callsites_per_binary = []

    for records in pcode_records_by_file.values():
        functions = {(record.get("sample_id"), record.get("function_entry"), record.get("function_name")) for record in records}
        function_counts.append(len(functions))
        ops_by_function: dict[tuple[Any, Any, Any], int] = defaultdict(int)
        for record in records:
            ops_by_function[(record.get("sample_id"), record.get("function_entry"), record.get("function_name"))] += 1
        pcode_ops_per_function.extend(ops_by_function.values())

    for records in callsite_records_by_file.values():
        callsites_per_binary.append(len(records))

    return {
        "analyzed_binaries": max(len(pcode_records_by_file), len(callsite_records_by_file)),
        "pcode_extraction_success": len(pcode_records_by_file),
        "callsite_extraction_success": len(callsite_records_by_file),
        "decompile_failure_count": len(error_records),
        "average_functions_per_binary": average(function_counts),
        "average_pcode_ops_per_function": average(pcode_ops_per_function),
        "average_callsites_per_binary": average(callsites_per_binary),
    }


def trace_stats(trace_records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_candidate_count": sum(1 for record in trace_records if record.get("source")),
        "sink_candidate_count": sum(1 for record in trace_records if record.get("sink")),
        "source_sink_pair_count": len(trace_records),
        "path_found_count": sum(1 for record in trace_records if record.get("path_found") is True),
        "path_not_found_count": sum(1 for record in trace_records if record.get("path_found") is False),
        "path_unknown_count": sum(1 for record in trace_records if record.get("path_found") == "unknown"),
    }


def leakage_stats(dataset_records: list[dict[str, Any]]) -> dict[str, Any]:
    warnings: list[str] = []
    failed = 0
    for record in dataset_records:
        metadata = record.get("metadata", {})
        result = check_model_input(
            record.get("model_input", {}),
            source_filename=Path(str(metadata.get("source_path", ""))).name,
            original_function_name=str(metadata.get("original_function_name", "")),
        )
        if result.status == "failed":
            failed += 1
            warnings.append(f"{record.get('record_id', '<unknown>')}: {', '.join(result.findings)}")
    return {
        "checked_records": len(dataset_records),
        "failed": failed,
        "warnings": warnings,
    }


def sample_trace_records(trace_records: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for record in trace_records[:limit]:
        samples.append(
            {
                "sample_id": record.get("sample_id", ""),
                "function_id": record.get("function_id", ""),
                "source_location": record.get("source", {}).get("source_location", ""),
                "sink_location": record.get("sink", {}).get("sink_location", ""),
                "path_found": record.get("path_found", ""),
                "reason": record.get("reason", ""),
                "trace_op_count": len(record.get("trace_ops", [])),
            }
        )
    return samples


def render_markdown(summary: dict[str, Any]) -> str:
    build = summary["build_summary"]
    ghidra = summary["ghidra_summary"]
    trace = summary["trace_summary"]
    leakage = summary["leakage_summary"]
    lines = [
        "# MVP Stats Report",
        "",
        "## Build Summary",
        "",
        f"- Attempted: {build['attempted']}",
        f"- Success: {build['success']}",
        f"- Failed: {build['failed']}",
        f"- Compiler: {format_counter(build['compiler'])}",
        f"- Opt level: {format_counter(build['opt_level'])}",
        "",
        "## Ghidra Extraction Summary",
        "",
        f"- Analyzed binaries: {ghidra['analyzed_binaries']}",
        f"- P-code extraction success: {ghidra['pcode_extraction_success']}",
        f"- Callsite extraction success: {ghidra['callsite_extraction_success']}",
        f"- Decompile failure count: {ghidra['decompile_failure_count']}",
        f"- Average functions per binary: {ghidra['average_functions_per_binary']:.2f}",
        f"- Average P-code ops per function: {ghidra['average_pcode_ops_per_function']:.2f}",
        f"- Average callsites per binary: {ghidra['average_callsites_per_binary']:.2f}",
        "",
        "## Trace Summary",
        "",
        f"- Source candidate count: {trace['source_candidate_count']}",
        f"- Sink candidate count: {trace['sink_candidate_count']}",
        f"- Source-sink pair count: {trace['source_sink_pair_count']}",
        f"- Path found: {trace['path_found_count']}",
        f"- Path not found: {trace['path_not_found_count']}",
        f"- Path unknown: {trace['path_unknown_count']}",
        "",
        "## Dataset Leakage Check",
        "",
        f"- Checked records: {leakage['checked_records']}",
        f"- Failed: {leakage['failed']}",
    ]
    if leakage["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        for warning in leakage["warnings"]:
            lines.append(f"- {warning}")
    lines.extend(["", "## Sample Records", ""])
    if not summary["sample_records"]:
        lines.append("No trace records available.")
    else:
        for sample in summary["sample_records"]:
            lines.extend(
                [
                    f"### {sample['sample_id']} / {sample['function_id']}",
                    "",
                    f"- Source location: {sample['source_location']}",
                    f"- Sink location: {sample['sink_location']}",
                    f"- Path found: {sample['path_found']}",
                    f"- Reason: {sample['reason']}",
                    f"- Trace op count: {sample['trace_op_count']}",
                    "",
                ]
            )
    return "\n".join(lines) + "\n"


def count_files(root: Path, pattern: str, cwe_scope: set[str] | None) -> int:
    if not root.exists():
        return 0
    return sum(1 for path in root.rglob(pattern) if cwe_scope is None or any(part in cwe_scope for part in path.parts))


def count_ghidra_successes(pcode_dir: Path, cwe_scope: set[str] | None) -> int:
    if not pcode_dir.exists():
        return 0
    success = 0
    for pcode_path in pcode_dir.rglob("*.pcode.jsonl"):
        if cwe_scope is not None and not any(part in cwe_scope for part in pcode_path.parts):
            continue
        sample = pcode_path.name.removesuffix(".pcode.jsonl")
        if pcode_path.with_name(f"{sample}.callsites.jsonl").exists():
            success += 1
    return success


def count_ghidra_failures(pcode_dir: Path, cwe_scope: set[str] | None) -> int:
    if not pcode_dir.exists():
        return 0
    return sum(
        1
        for path in pcode_dir.rglob("*.ghidra_errors.jsonl")
        if path.stat().st_size > 0 and (cwe_scope is None or any(part in cwe_scope for part in path.parts))
    )


def average(values: list[int]) -> float:
    return sum(values) / len(values) if values else 0.0


def format_counter(counter: dict[str, int]) -> str:
    if not counter:
        return "n/a"
    return ", ".join(f"{key}={value}" for key, value in sorted(counter.items()))


if __name__ == "__main__":
    raise SystemExit(main())
