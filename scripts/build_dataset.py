#!/usr/bin/env python3
"""Build dataset records from LLMDFA output plus Ghidra evidence."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.dataset.writer import build_dataset_record, write_jsonl
from src.ghidra_evidence.linker import attach_ghidra_evidence
from src.ghidra_evidence.loader import evidence_paths_for_metadata, load_sample_evidence
from src.juliet.discovery import load_config, resolve_cwe_scope
from src.llmdfa_adapter.output_parser import parse_llmdfa_output

LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of LLMDFA records to process.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing dataset output when present.")
    parser.add_argument("--force", action="store_true", help="Regenerate outputs even if they exist.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    summary = run_build_dataset(
        args.config,
        cli_cwes=args.cwe,
        limit=args.limit,
        resume=args.resume,
        force=args.force,
    )
    logging.info(
        "Dataset summary: llmdfa_records=%s records=%s dataset=%s leakage_failed=%s",
        summary["llmdfa_records"],
        summary["records"],
        summary["dataset_path"],
        summary["leakage_failed"],
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
    ghidra_config = config.get("ghidra", {})
    llmdfa_config = config.get("llmdfa", {})

    pcode_dir = Path(ghidra_config.get("output_dir", dataset_config.get("pcode_dir", "data/pcode")))
    output_dir = Path(dataset_config.get("output_dir", "data/datasets"))
    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    metadata_path = binaries_dir / "build_metadata.jsonl"
    conversion_manifest_path = Path(llmdfa_config.get("input_manifest", "data/llmdfa_inputs/manifest.jsonl"))
    parsed_llmdfa_path = Path(llmdfa_config.get("parsed_output_path", "data/llmdfa_outputs/parsed_results.jsonl"))
    llmdfa_output_root = Path(llmdfa_config.get("output_root", "data/llmdfa_outputs"))

    cwe_scope = resolve_cwe_scope(config, cli_cwes)
    dataset_path = output_dir / dataset_name(config, cwe_scope)
    if resume and not force and dataset_path.exists():
        records = read_jsonl(dataset_path)
        return {
            "llmdfa_records": len(records),
            "records": len(records),
            "dataset_path": dataset_path,
            "leakage_failed": sum(1 for record in records if record.get("leakage_check", {}).get("status") == "failed"),
            "resumed": True,
        }

    metadata_by_sample = index_build_metadata(read_jsonl(metadata_path), cwe_scope=cwe_scope)
    conversions = read_jsonl(conversion_manifest_path)
    conversions_by_source = index_conversions_by_source(conversions)
    conversions_by_function = {str(record.get("function_id", "")): record for record in conversions}
    llmdfa_records = load_llmdfa_records(parsed_llmdfa_path, llmdfa_output_root)

    dataset_records = []
    evidence_cache: dict[tuple[str, str, str, str], Any] = {}
    for llmdfa_record in llmdfa_records:
        conversion = find_conversion(llmdfa_record, conversions_by_source, conversions_by_function)
        if not conversion:
            LOGGER.warning("Skipping LLMDFA record without conversion mapping: %s", llmdfa_record.get("record_id", ""))
            continue

        original_sample_id = str(conversion.get("original_sample_id", ""))
        metadata = metadata_by_sample.get(original_sample_id)
        if metadata is None:
            LOGGER.warning("Skipping LLMDFA record without build metadata: %s", original_sample_id)
            continue

        evidence = load_cached_evidence(
            evidence_cache,
            pcode_dir=pcode_dir,
            metadata=metadata,
            conversions=conversions,
        )
        attached = attach_ghidra_evidence(
            llmdfa_record,
            evidence,
            function_entry=str(conversion.get("function_entry", "")),
            function_id=str(conversion.get("function_id", "")),
        )
        dataset_records.append(
            build_dataset_record(
                attached,
                conversion=conversion,
                metadata=metadata,
                ghidra_evidence=attached.get("ghidra_evidence", {}),
            )
        )
        if limit is not None and len(dataset_records) >= limit:
            break

    write_jsonl(dataset_path, dataset_records)
    return {
        "llmdfa_records": len(llmdfa_records),
        "records": len(dataset_records),
        "dataset_path": dataset_path,
        "leakage_failed": sum(1 for record in dataset_records if record.leakage_check.status == "failed"),
        "resumed": False,
    }


def load_llmdfa_records(parsed_path: Path, output_root: Path) -> list[dict[str, Any]]:
    if parsed_path.exists():
        return read_jsonl(parsed_path)
    parsed = [record.to_dict() for record in parse_llmdfa_output(output_root)]
    if parsed:
        write_jsonl(parsed_path, parsed)
    return parsed


def load_cached_evidence(
    cache: dict[tuple[str, str, str, str], Any],
    *,
    pcode_dir: Path,
    metadata: dict[str, Any],
    conversions: list[dict[str, Any]],
) -> Any:
    key = (
        str(metadata.get("sample_id", "")),
        str(metadata.get("cwe", "")),
        str(metadata.get("variant", "")),
        str(metadata.get("opt_level", "")),
    )
    if key in cache:
        return cache[key]
    pcode_path, callsites_path = evidence_paths_for_metadata(pcode_dir, metadata)
    function_id_by_entry = {
        str(record.get("function_entry", "")): str(record.get("function_id", ""))
        for record in conversions
        if str(record.get("original_sample_id", "")) == key[0]
    }
    evidence = load_sample_evidence(
        pcode_path,
        callsites_path,
        sample_id=key[0],
        function_id_by_entry=function_id_by_entry,
    )
    cache[key] = evidence
    return evidence


def find_conversion(
    llmdfa_record: dict[str, Any],
    conversions_by_source: dict[str, dict[str, Any]],
    conversions_by_function: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    source_file = str(llmdfa_record.get("source_file", ""))
    candidates = [
        source_file,
        Path(source_file).as_posix(),
        Path(source_file).name,
    ]
    for candidate in candidates:
        if candidate in conversions_by_source:
            return conversions_by_source[candidate]

    function_id = str(llmdfa_record.get("function_id", ""))
    if function_id and function_id in conversions_by_function:
        return conversions_by_function[function_id]
    return None


def index_conversions_by_source(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        source_path = str(record.get("source_path", ""))
        if not source_path:
            continue
        indexed[source_path] = record
        indexed[Path(source_path).as_posix()] = record
        indexed[Path(source_path).name] = record
    return indexed


def index_build_metadata(records: list[dict[str, Any]], *, cwe_scope: set[str] | None) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.get("compile_success") is not True:
            continue
        cwe = str(record.get("cwe", ""))
        if cwe_scope is not None and cwe not in cwe_scope:
            continue
        indexed[str(record.get("sample_id", ""))] = record
    return indexed


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


def dataset_name(config: dict[str, Any], cwe_scope: set[str] | None) -> str:
    dataset_config = config.get("dataset", {})
    if dataset_config.get("filename"):
        return str(dataset_config["filename"])
    if cwe_scope == {"CWE78"}:
        return "mvp_cwe78.jsonl"
    if cwe_scope and len(cwe_scope) == 1:
        return f"{next(iter(cwe_scope)).lower()}.jsonl"
    return "mvp_dataset.jsonl"


if __name__ == "__main__":
    raise SystemExit(main())
