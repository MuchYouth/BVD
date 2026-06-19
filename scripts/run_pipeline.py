#!/usr/bin/env python3
"""Run the full MVP pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_dataset import run_build_dataset
from scripts.report_mvp_stats import run_report
from scripts.run_ghidra_extract import run_extract
from src.juliet.builder import run_build
from src.juliet.discovery import load_config, resolve_cwe_scope, run_discovery
from src.llmdfa_adapter.input_converter import convert_decompiled_tree
from src.llmdfa_adapter.output_parser import parse_llmdfa_output, write_jsonl as write_llmdfa_jsonl
from src.llmdfa_adapter.runner import run_llmdfa

LOGGER = logging.getLogger(__name__)

STAGES = [
    "discover_juliet",
    "build_juliet",
    "run_ghidra_extract",
    "convert_ghidra_to_llmdfa_input",
    "run_llmdfa",
    "parse_llmdfa_output",
    "attach_ghidra_evidence",
    "build_dataset",
    "report",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--start-from", choices=STAGES, default="discover_juliet", help="Pipeline stage to start from.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of testcases/samples to process.")
    parser.add_argument("--dry-run", action="store_true", help="Plan stages without running build/Ghidra/dataset side effects where supported.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing successful outputs.")
    parser.add_argument("--force", action="store_true", help="Regenerate outputs even if they exist.")
    parser.add_argument("--jobs", type=int, help="Number of worker jobs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    LOGGER.info(
        "run_pipeline started config=%s start_from=%s cwe=%s limit=%s dry_run=%s resume=%s force=%s jobs=%s",
        args.config,
        args.start_from,
        args.cwe,
        args.limit,
        args.dry_run,
        args.resume,
        args.force,
        args.jobs,
    )
    summary = run_pipeline(
        args.config,
        start_from=args.start_from,
        cli_cwes=args.cwe,
        limit=args.limit,
        dry_run=args.dry_run,
        resume=args.resume,
        force=args.force,
        jobs=args.jobs,
    )
    print_summary(summary)
    return 0


def run_pipeline(
    config_path: str | Path,
    *,
    start_from: str = "discover_juliet",
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    resume: bool = False,
    force: bool = False,
    jobs: int | None = None,
) -> dict[str, Any]:
    config = load_config(config_path)
    start_index = STAGES.index(start_from)
    stage_errors: dict[str, str] = {}

    def should_run(stage: str) -> bool:
        return STAGES.index(stage) >= start_index

    if should_run("discover_juliet"):
        run_stage(
            "discover_juliet",
            lambda: run_discovery(config_path, cli_cwes=cli_cwes, limit=limit, dry_run=dry_run),
            stage_errors,
        )
    if should_run("build_juliet"):
        run_stage(
            "build_juliet",
            lambda: run_build(
                config_path,
                cli_cwes=cli_cwes,
                limit=limit,
                dry_run=dry_run,
                resume=resume,
                force=force,
                jobs=jobs,
            ),
            stage_errors,
        )
    if should_run("run_ghidra_extract") and not dry_run:
        run_stage(
            "run_ghidra_extract",
            lambda: run_extract(config_path, cli_cwes=cli_cwes, limit=limit, resume=resume, force=force, jobs=jobs),
            stage_errors,
        )
    elif should_run("run_ghidra_extract"):
        LOGGER.info("DRY-RUN skipping ghidra execution")

    if should_run("convert_ghidra_to_llmdfa_input") and not dry_run:
        run_stage(
            "convert_ghidra_to_llmdfa_input",
            lambda: run_convert_ghidra_to_llmdfa_input(config),
            stage_errors,
        )
    elif should_run("convert_ghidra_to_llmdfa_input"):
        LOGGER.info("DRY-RUN skipping LLMDFA input conversion")

    if should_run("run_llmdfa") and not dry_run:
        run_stage(
            "run_llmdfa",
            lambda: run_llmdfa_from_config(config, dry_run=dry_run),
            stage_errors,
        )
    elif should_run("run_llmdfa"):
        LOGGER.info("DRY-RUN skipping LLMDFA execution")

    if should_run("parse_llmdfa_output") and not dry_run:
        run_stage(
            "parse_llmdfa_output",
            lambda: run_parse_llmdfa_output(config),
            stage_errors,
        )
    elif should_run("parse_llmdfa_output"):
        LOGGER.info("DRY-RUN skipping LLMDFA output parsing")

    if should_run("attach_ghidra_evidence"):
        LOGGER.info("Stage attach_ghidra_evidence is performed inside build_dataset")

    if should_run("build_dataset") and not dry_run:
        run_stage(
            "build_dataset",
            lambda: run_build_dataset(config_path, cli_cwes=cli_cwes, limit=limit, resume=resume, force=force),
            stage_errors,
        )
    elif should_run("build_dataset"):
        LOGGER.info("DRY-RUN skipping dataset execution")

    if should_run("report"):
        run_stage(
            "report",
            lambda: run_report(config_path, cli_cwes=cli_cwes, limit=limit),
            stage_errors,
        )

    summary = collect_summary(config, cli_cwes=cli_cwes)
    summary["stage_errors"] = stage_errors
    write_pipeline_status(config, summary)
    return summary


def run_convert_ghidra_to_llmdfa_input(config: dict[str, Any]) -> dict[str, Any]:
    dataset_config = config.get("dataset", {})
    ghidra_config = config.get("ghidra", {})
    llmdfa_config = config.get("llmdfa", {})
    input_root = Path(ghidra_config.get("output_dir", dataset_config.get("pcode_dir", "data/pcode")))
    output_root = Path(llmdfa_config.get("input_root", "data/llmdfa_inputs"))
    language = str(llmdfa_config.get("language", "c"))
    manifest_name = Path(str(llmdfa_config.get("input_manifest", "data/llmdfa_inputs/manifest.jsonl"))).name
    return convert_decompiled_tree(input_root, output_root, language=language, manifest_name=manifest_name).to_dict()


def run_llmdfa_from_config(config: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    llmdfa_config = config.get("llmdfa", {})
    result = run_llmdfa(
        llmdfa_root=Path(llmdfa_config.get("root", "external/LLMDFA")),
        input_manifest=Path(llmdfa_config.get("input_manifest", "data/llmdfa_inputs/manifest.jsonl")),
        output_root=Path(llmdfa_config.get("output_root", "data/llmdfa_outputs")),
        bug_type=str(llmdfa_config.get("bug_type", "osci")),
        model_name=str(llmdfa_config.get("model_name", "gpt-4o-mini")),
        analysis_mode=str(llmdfa_config.get("analysis_mode", "single")),
        solving_refine_number=int(llmdfa_config.get("solving_refine_number", 3)),
        syn_parser=bool(llmdfa_config.get("syn_parser", True)),
        fscot=bool(llmdfa_config.get("fscot", True)),
        syn_solver=bool(llmdfa_config.get("syn_solver", True)),
        dry_run=dry_run or bool(llmdfa_config.get("dry_run", False)),
        allow_upstream_benchmark_run=bool(llmdfa_config.get("allow_upstream_benchmark_run", False)),
    )
    return result.to_dict()


def run_parse_llmdfa_output(config: dict[str, Any]) -> dict[str, Any]:
    llmdfa_config = config.get("llmdfa", {})
    output_root = Path(llmdfa_config.get("output_root", "data/llmdfa_outputs"))
    parsed_path = Path(llmdfa_config.get("parsed_output_path", "data/llmdfa_outputs/parsed_results.jsonl"))
    records = [record.to_dict() for record in parse_llmdfa_output(output_root)]
    written = write_llmdfa_jsonl(parsed_path, records)
    return {"records": len(records), "written": written, "parsed_path": parsed_path.as_posix()}


def run_stage(stage: str, func: Callable[[], Any], stage_errors: dict[str, str]) -> None:
    try:
        LOGGER.info("Stage %s started", stage)
        result = func()
        LOGGER.info("Stage %s completed: %s", stage, result)
    except Exception as exc:  # noqa: BLE001 - pipeline should continue and report the failed stage.
        LOGGER.exception("Stage %s failed: %s", stage, exc)
        stage_errors[stage] = str(exc)


def collect_summary(config: dict[str, Any], *, cli_cwes: Iterable[str] | None = None) -> dict[str, Any]:
    juliet_config = config.get("juliet", {})
    dataset_config = config.get("dataset", {})
    ghidra_config = config.get("ghidra", {})
    cwe_scope = resolve_cwe_scope(config, cli_cwes)

    manifest_path = Path(juliet_config.get("manifest_path", "data/manifests/juliet_manifest.jsonl"))
    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    build_metadata_path = binaries_dir / "build_metadata.jsonl"
    pcode_dir = Path(ghidra_config.get("output_dir", dataset_config.get("pcode_dir", "data/pcode")))
    output_dir = Path(dataset_config.get("output_dir", "data/datasets"))
    llmdfa_config = config.get("llmdfa", {})
    llmdfa_input_root = Path(llmdfa_config.get("input_root", "data/llmdfa_inputs"))
    llmdfa_parsed_path = Path(llmdfa_config.get("parsed_output_path", "data/llmdfa_outputs/parsed_results.jsonl"))

    manifest_records = filter_by_cwe(read_jsonl(manifest_path), cwe_scope)
    build_records = filter_by_cwe(read_jsonl(build_metadata_path), cwe_scope)
    dataset_records = read_dataset_records(output_dir, cwe_scope)

    pcode_files = count_files(pcode_dir, "*.pcode.jsonl", cwe_scope)
    callsite_files = count_files(pcode_dir, "*.callsites.jsonl", cwe_scope)
    decompiled_files = count_files(pcode_dir, "*.decompiled.jsonl", cwe_scope)
    llmdfa_input_files = count_files(llmdfa_input_root, "*.c", None) + count_files(llmdfa_input_root, "*.cpp", None)
    llmdfa_records = read_jsonl(llmdfa_parsed_path)

    return {
        "total_testcases": sum(1 for record in manifest_records if record.get("build_candidate") is True),
        "build_attempted": sum(1 for record in build_records if not record.get("skipped")),
        "build_success": sum(1 for record in build_records if record.get("compile_success") is True),
        "build_failed": sum(
            1 for record in build_records if record.get("compile_success") is not True and not record.get("skipped")
        ),
        "build_skipped": sum(1 for record in build_records if record.get("skipped")),
        "ghidra_attempted": max(pcode_files, callsite_files),
        "ghidra_success": count_ghidra_successes(pcode_dir, cwe_scope),
        "ghidra_failed": count_ghidra_failures(pcode_dir, cwe_scope),
        "decompiled_files": decompiled_files,
        "pcode_files": pcode_files,
        "callsite_files": callsite_files,
        "llmdfa_input_files": llmdfa_input_files,
        "llmdfa_records": len(llmdfa_records),
        "dataset_records": len(dataset_records),
        "leakage_failed_count": sum(1 for record in dataset_records if record.get("leakage_check", {}).get("status") == "failed"),
    }


def write_pipeline_status(config: dict[str, Any], summary: dict[str, Any]) -> None:
    juliet_config = config.get("juliet", {})
    dataset_config = config.get("dataset", {})
    ghidra_config = config.get("ghidra", {})
    manifest_path = Path(juliet_config.get("manifest_path", "data/manifests/juliet_manifest.jsonl"))
    status_path = manifest_path.parent / "pipeline_status.jsonl"
    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    pcode_dir = Path(ghidra_config.get("output_dir", dataset_config.get("pcode_dir", "data/pcode")))
    output_dir = Path(dataset_config.get("output_dir", "data/datasets"))

    records: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for build in read_jsonl(binaries_dir / "build_metadata.jsonl"):
        key = (
            str(build.get("sample_id", "")),
            str(build.get("cwe", "")),
            str(build.get("variant", "")),
            str(build.get("opt_level", "")),
        )
        build_status = "success" if build.get("compile_success") is True else "failed"
        if build.get("skipped"):
            build_status = "skipped"
        last_error = ""
        if build.get("compile_success") is not True:
            last_error = str(build.get("compile_stderr", "") or build.get("skip_reason", ""))[:500]
        records[key] = {
            "sample_id": key[0],
            "cwe": key[1],
            "variant": key[2],
            "opt_level": key[3],
            "build_status": build_status,
            "ghidra_status": "unknown",
            "llmdfa_status": "unknown",
            "dataset_status": "unknown",
            "last_error": last_error,
            "updated_at": utc_now(),
        }

    for key, record in records.items():
        sample_id, cwe, variant, opt_level = key
        sample_pcode_dir = pcode_dir / cwe / variant / opt_level
        pcode_path = sample_pcode_dir / f"{sample_id}.pcode.jsonl"
        callsite_path = sample_pcode_dir / f"{sample_id}.callsites.jsonl"
        decompiled_path = sample_pcode_dir / f"{sample_id}.decompiled.jsonl"
        record["ghidra_status"] = "success" if decompiled_path.exists() and pcode_path.exists() and callsite_path.exists() else "failed"
        record["llmdfa_status"] = "unknown"
        record["dataset_status"] = "success" if dataset_contains_sample(output_dir, sample_id) else "failed"
        record["updated_at"] = utc_now()

    status_path.parent.mkdir(parents=True, exist_ok=True)
    with status_path.open("w", encoding="utf-8") as handle:
        for record in records.values():
            handle.write(json.dumps(record, sort_keys=True) + "\n")


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


def read_dataset_records(output_dir: Path, cwe_scope: set[str] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in output_dir.glob("*.jsonl"):
        records.extend(filter_by_cwe(read_jsonl(path), cwe_scope))
    return records


def count_files(root: Path, pattern: str, cwe_scope: set[str] | None) -> int:
    if not root.exists():
        return 0
    count = 0
    for path in root.rglob(pattern):
        if cwe_scope is not None and not any(part in cwe_scope for part in path.parts):
            continue
        count += 1
    return count


def count_ghidra_successes(pcode_dir: Path, cwe_scope: set[str] | None) -> int:
    if not pcode_dir.exists():
        return 0
    success = 0
    for pcode_path in pcode_dir.rglob("*.pcode.jsonl"):
        if cwe_scope is not None and not any(part in cwe_scope for part in pcode_path.parts):
            continue
        sample = pcode_path.name.removesuffix(".pcode.jsonl")
        callsite_path = pcode_path.with_name(f"{sample}.callsites.jsonl")
        decompiled_path = pcode_path.with_name(f"{sample}.decompiled.jsonl")
        if decompiled_path.exists() and callsite_path.exists():
            success += 1
    return success


def count_ghidra_failures(pcode_dir: Path, cwe_scope: set[str] | None) -> int:
    if not pcode_dir.exists():
        return 0
    failed = 0
    for error_path in pcode_dir.rglob("*.ghidra_errors.jsonl"):
        if cwe_scope is not None and not any(part in cwe_scope for part in error_path.parts):
            continue
        if error_path.stat().st_size > 0:
            failed += 1
    return failed


def dataset_contains_sample(output_dir: Path, sample_id: str) -> bool:
    for path in output_dir.glob("*.jsonl"):
        for record in read_jsonl(path):
            if str(record.get("sample_id", "")) == sample_id:
                return True
    return False


def print_summary(summary: dict[str, Any]) -> None:
    keys = [
        "total_testcases",
        "build_attempted",
        "build_success",
        "build_failed",
        "build_skipped",
        "ghidra_attempted",
        "ghidra_success",
        "ghidra_failed",
        "decompiled_files",
        "pcode_files",
        "callsite_files",
        "llmdfa_input_files",
        "llmdfa_records",
        "dataset_records",
        "leakage_failed_count",
    ]
    for key in keys:
        print(f"{key}: {summary.get(key, 0)}")
    if summary.get("stage_errors"):
        print("stage_errors:")
        for stage, error in summary["stage_errors"].items():
            print(f"  {stage}: {error}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
