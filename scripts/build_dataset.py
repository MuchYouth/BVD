#!/usr/bin/env python3
"""Build trace candidates and dataset records."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.analysis.rule_registry import RuleRegistry
from src.analysis.llm_trace import client_from_config, review_trace_with_client
from src.analysis.source_sink import extract_source_sink_pairs
from src.analysis.trace_builder import build_trace_candidates
from src.dataset.writer import build_dataset_record, write_jsonl
from src.juliet.discovery import load_config, resolve_cwe_scope
from src.pcode.normalizer import group_by_function
from src.pcode.parser import load_callsites_jsonl, load_pcode_jsonl

LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of samples to process.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing successful trace outputs.")
    parser.add_argument("--force", action="store_true", help="Regenerate outputs even if they exist.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("build_dataset started")
    summary = run_build_dataset(
        args.config,
        cli_cwes=args.cwe,
        limit=args.limit,
        resume=args.resume,
        force=args.force,
    )
    logging.info(
        "Dataset summary: samples=%s traces=%s records=%s dataset=%s",
        summary["samples"],
        summary["traces"],
        summary["records"],
        summary["dataset_path"],
    )
    return 0


def run_build_dataset(
    config_path: str | Path,
    *,
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
    resume: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    config = load_config(config_path)
    dataset_config = config.get("dataset", {})
    analysis_config = config.get("analysis", {})
    pcode_dir = Path(dataset_config.get("pcode_dir", "data/pcode"))
    traces_dir = Path(dataset_config.get("traces_dir", "data/traces"))
    output_dir = Path(dataset_config.get("output_dir", "data/datasets"))
    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    metadata_path = binaries_dir / "build_metadata.jsonl"

    cwe_scope = resolve_cwe_scope(config, cli_cwes)
    registry = RuleRegistry(analysis_config.get("rule_dir", "configs/cwe_rules"))
    llm_client = client_from_config(config)
    llm_enabled = bool(config.get("llm", {}).get("enabled", False))
    build_records = select_build_records(read_jsonl(metadata_path), cwe_scope=cwe_scope, limit=limit)

    dataset_records = []
    total_traces = 0
    processed_samples = 0

    for metadata in build_records:
        cwe = str(metadata.get("cwe", ""))
        rule = registry.get_rule(cwe)
        if rule.is_unsupported:
            LOGGER.warning("Skipping unsupported CWE during dataset build: %s", cwe)
            continue

        sample_id = str(metadata["sample_id"])
        variant = str(metadata["variant"])
        opt_level = str(metadata["opt_level"])
        sample_pcode_dir = pcode_dir / cwe / variant / opt_level
        pcode_path = sample_pcode_dir / f"{sample_id}.pcode.jsonl"
        callsites_path = sample_pcode_dir / f"{sample_id}.callsites.jsonl"
        trace_path = traces_dir / cwe / variant / opt_level / f"{sample_id}.trace.jsonl"

        if resume and not force and trace_path.exists():
            LOGGER.info("Skipping existing trace output for %s", sample_id)
            continue

        pcode_result = load_pcode_jsonl(pcode_path)
        callsite_result = load_callsites_jsonl(callsites_path)
        if pcode_result.errors or callsite_result.errors:
            LOGGER.warning(
                "Parser errors for %s: pcode_errors=%s callsite_errors=%s",
                sample_id,
                len(pcode_result.errors),
                len(callsite_result.errors),
            )

        functions = group_by_function(
            pcode_result.records,
            callsite_result.records,
            anonymize_symbols=bool(dataset_config.get("anonymize_symbols", True)),
        )
        sample_traces = []
        sample_records = []

        for function in functions:
            pairs = extract_source_sink_pairs(
                [function],
                rule,
                unsupported_cwe_policy=analysis_config.get("unsupported_cwe_policy", "record_and_skip"),
            )
            traces = build_trace_candidates(function.ops, pairs, trace_type=str(rule.trace.get("type", "")))
            total_traces += len(traces)
            for trace in traces:
                trace_payload = asdict(trace)
                llm_review = {}
                if llm_enabled:
                    llm_review = review_trace_with_client(
                        llm_client,
                        function_ops=[op.to_dict() for op in function.ops],
                        source=trace_payload["source"],
                        sink=trace_payload["sink"],
                        trace_candidate={
                            "path_found": trace.path_found,
                            "trace_ops": trace.trace_ops,
                            "reason": trace.reason,
                            "analysis_mode": trace.analysis_mode,
                            "trace_type": trace.trace_type,
                        },
                    ).to_dict()
                    trace_payload["llm_review"] = llm_review
                sample_traces.append(trace_payload)
                sample_records.append(build_dataset_record(trace, function=function, metadata=metadata, llm_review=llm_review))

        write_jsonl(trace_path, sample_traces)
        dataset_records.extend(sample_records)
        processed_samples += 1

    dataset_path = output_dir / dataset_name(config, cwe_scope)
    write_jsonl(dataset_path, dataset_records)
    return {
        "samples": processed_samples,
        "traces": total_traces,
        "records": len(dataset_records),
        "dataset_path": dataset_path,
    }


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    jsonl_path = Path(path)
    if not jsonl_path.exists():
        LOGGER.warning("JSONL input does not exist: %s", jsonl_path)
        return []
    records: list[dict[str, Any]] = []
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                LOGGER.warning("Skipping invalid JSON at %s:%s: %s", jsonl_path, line_number, exc)
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def select_build_records(
    records: Iterable[dict[str, Any]],
    *,
    cwe_scope: set[str] | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for record in records:
        if record.get("compile_success") is not True:
            continue
        cwe = str(record.get("cwe", ""))
        if cwe_scope is not None and cwe not in cwe_scope:
            continue
        key = (
            str(record.get("sample_id", "")),
            cwe,
            str(record.get("variant", "")),
            str(record.get("opt_level", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(record)
        if limit is not None and len(selected) >= limit:
            break
    return selected


def dataset_name(config: dict[str, Any], cwe_scope: set[str] | None) -> str:
    if cwe_scope == {"CWE78"}:
        return "mvp_cwe78.jsonl"
    if cwe_scope and len(cwe_scope) == 1:
        return f"{next(iter(cwe_scope)).lower()}.jsonl"
    return "mvp_dataset.jsonl"


if __name__ == "__main__":
    raise SystemExit(main())
