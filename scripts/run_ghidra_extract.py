#!/usr/bin/env python3
"""Run Ghidra headless decompile extraction with P-code evidence."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.juliet.discovery import load_config, resolve_cwe_scope

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class GhidraJob:
    sample_id: str
    cwe: str
    variant: str
    opt_level: str
    binary_path: Path
    output_dir: Path
    decompiled_path: Path
    pcode_path: Path
    callsites_path: Path
    errors_path: Path
    log_path: Path
    project_dir: Path
    project_name: str
    script_dir: Path
    script_name: str
    analyze_headless: Path
    timeout_sec: int


@dataclass(frozen=True)
class GhidraSummary:
    planned: int
    attempted: int
    succeeded: int
    failed: int
    skipped: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml", help="Path to pipeline config YAML.")
    parser.add_argument("--cwe", action="append", help="CWE filter such as CWE78, or all. Can be repeated.")
    parser.add_argument("--limit", type=int, help="Maximum number of binaries to process.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing successful outputs.")
    parser.add_argument("--force", action="store_true", help="Re-extract outputs even if they exist.")
    parser.add_argument("--jobs", type=int, help="Number of worker jobs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("run_ghidra_extract started")
    summary = run_extract(
        args.config,
        cli_cwes=args.cwe,
        limit=args.limit,
        resume=args.resume if args.resume else None,
        force=args.force if args.force else None,
        jobs=args.jobs,
    )
    logging.info(
        "Ghidra summary: planned=%s attempted=%s succeeded=%s failed=%s skipped=%s",
        summary.planned,
        summary.attempted,
        summary.succeeded,
        summary.failed,
        summary.skipped,
    )
    return 0


def run_extract(
    config_path: str | Path,
    *,
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
    resume: bool | None = None,
    force: bool | None = None,
    jobs: int | None = None,
) -> GhidraSummary:
    config = load_config(config_path)
    dataset_config = config.get("dataset", {})
    ghidra_config = config.get("ghidra", {})

    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    metadata_path = binaries_dir / "build_metadata.jsonl"
    output_root = Path(ghidra_config.get("output_dir", dataset_config.get("pcode_dir", "data/pcode")))
    project_dir = Path(ghidra_config.get("project_dir", "data/ghidra_projects"))
    script_dir = Path(ghidra_config.get("script_dir", "ghidra_scripts"))
    timeout_sec = int(ghidra_config.get("timeout_sec", 180))
    effective_jobs = int(jobs or ghidra_config.get("jobs", 1) or 1)
    effective_resume = bool(ghidra_config.get("resume", True)) if resume is None else resume
    effective_force = bool(ghidra_config.get("force", False)) if force is None else force

    build_records = read_jsonl(metadata_path)
    cwe_scope = resolve_cwe_scope(config, cli_cwes)
    selected = select_successful_binaries(build_records, cwe_scope=cwe_scope, limit=limit)
    if not selected:
        LOGGER.info("No compile_success=true binaries selected from %s", metadata_path)
        return GhidraSummary(planned=0, attempted=0, succeeded=0, failed=0, skipped=0)

    analyze_headless = resolve_analyze_headless(ghidra_config.get("install_dir", ""))
    if analyze_headless is None:
        LOGGER.error(
            "Could not find Ghidra analyzeHeadless. Set ghidra.install_dir in configs/default.yaml "
            "to your Ghidra installation directory, for example /opt/ghidra_11.0_PUBLIC."
        )
        return GhidraSummary(planned=len(selected), attempted=0, succeeded=0, failed=len(selected), skipped=0)

    ghidra_jobs = [
        create_job(
            record,
            output_root=output_root,
            project_dir=project_dir,
            script_dir=script_dir,
            analyze_headless=analyze_headless,
            timeout_sec=timeout_sec,
        )
        for record in selected
    ]

    LOGGER.info("Selected %s successful binaries and planned %s Ghidra jobs", len(selected), len(ghidra_jobs))

    results: list[dict[str, Any]] = []
    if effective_jobs > 1 and len(ghidra_jobs) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_jobs) as executor:
            futures = [
                executor.submit(run_job, job, resume=effective_resume, force=effective_force)
                for job in ghidra_jobs
            ]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
    else:
        for job in ghidra_jobs:
            results.append(run_job(job, resume=effective_resume, force=effective_force))

    succeeded = sum(1 for result in results if result["success"])
    failed = sum(1 for result in results if not result["success"])
    skipped = sum(1 for result in results if result.get("skipped"))
    attempted = len(results) - skipped
    return GhidraSummary(
        planned=len(ghidra_jobs),
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
    )


def resolve_analyze_headless(install_dir_value: str) -> Path | None:
    install_dir = Path(install_dir_value)
    candidates: list[Path] = []
    if install_dir_value:
        candidates.extend(
            [
                install_dir / "support" / "analyzeHeadless",
                install_dir / "analyzeHeadless",
            ]
        )
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    jsonl_path = Path(path)
    if not jsonl_path.exists():
        LOGGER.warning("Input JSONL does not exist: %s", jsonl_path)
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


def select_successful_binaries(
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
        binary_path = Path(str(record.get("binary_path", "")))
        if not binary_path.exists():
            LOGGER.warning("Skipping missing binary from metadata: %s", binary_path)
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


def create_job(
    record: dict[str, Any],
    *,
    output_root: Path,
    project_dir: Path,
    script_dir: Path,
    analyze_headless: Path,
    timeout_sec: int,
) -> GhidraJob:
    sample_id = str(record["sample_id"])
    cwe = str(record["cwe"])
    variant = str(record["variant"])
    opt_level = str(record["opt_level"])
    output_dir = output_root / cwe / variant / opt_level
    project_name = f"{sample_id}_{variant}_{opt_level}"
    return GhidraJob(
        sample_id=sample_id,
        cwe=cwe,
        variant=variant,
        opt_level=opt_level,
        binary_path=Path(str(record["binary_path"])),
        output_dir=output_dir,
        decompiled_path=output_dir / f"{sample_id}.decompiled.jsonl",
        pcode_path=output_dir / f"{sample_id}.pcode.jsonl",
        callsites_path=output_dir / f"{sample_id}.callsites.jsonl",
        errors_path=output_dir / f"{sample_id}.ghidra_errors.jsonl",
        log_path=output_dir / f"{sample_id}.ghidra.log",
        project_dir=project_dir,
        project_name=project_name,
        script_dir=script_dir,
        script_name="DumpDecompileAndPcode.java",
        analyze_headless=analyze_headless,
        timeout_sec=timeout_sec,
    )


def run_job(job: GhidraJob, *, resume: bool, force: bool) -> dict[str, Any]:
    job.output_dir.mkdir(parents=True, exist_ok=True)
    job.project_dir.mkdir(parents=True, exist_ok=True)

    if resume and not force and extraction_outputs_exist(job):
        LOGGER.info("Skipping existing Ghidra outputs for %s", job.sample_id)
        return {"sample_id": job.sample_id, "success": True, "skipped": True}

    command = command_for_job(job)
    started_at = utc_now()
    LOGGER.info("Running Ghidra extraction for %s -> %s", job.binary_path, job.output_dir)

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=job.timeout_sec,
        )
        log_text = format_log(command, started_at, utc_now(), completed.returncode, completed.stdout, completed.stderr)
        write_text(job.log_path, log_text)
        success = (
            completed.returncode == 0
            and job.decompiled_path.exists()
            and job.pcode_path.exists()
            and job.callsites_path.exists()
            and job.errors_path.exists()
        )
        if not success:
            append_ghidra_error(job, "ghidra_failed", f"returncode={completed.returncode}")
        return {"sample_id": job.sample_id, "success": success, "skipped": False}
    except subprocess.TimeoutExpired as exc:
        finished_at = utc_now()
        stdout = decode_process_text(exc.stdout)
        stderr = decode_process_text(exc.stderr)
        write_text(job.log_path, format_log(command, started_at, finished_at, None, stdout, stderr))
        append_ghidra_error(job, "ghidra_timeout", f"timeout after {job.timeout_sec}s")
        return {"sample_id": job.sample_id, "success": False, "skipped": False}
    except OSError as exc:
        write_text(job.log_path, format_log(command, started_at, utc_now(), None, "", str(exc)))
        append_ghidra_error(job, "ghidra_os_error", str(exc))
        return {"sample_id": job.sample_id, "success": False, "skipped": False}


def command_for_job(job: GhidraJob) -> list[str]:
    return [
        str(job.analyze_headless),
        str(job.project_dir),
        job.project_name,
        "-import",
        str(job.binary_path),
        "-overwrite",
        "-scriptPath",
        str(job.script_dir),
        "-postScript",
        job.script_name,
        job.sample_id,
        str(job.output_dir),
        "-deleteProject",
    ]


def extraction_outputs_exist(job: GhidraJob) -> bool:
    return (
        job.decompiled_path.exists()
        and job.pcode_path.exists()
        and job.callsites_path.exists()
        and job.errors_path.exists()
    )


def append_ghidra_error(job: GhidraJob, error_type: str, message: str) -> None:
    record = {
        "sample_id": job.sample_id,
        "binary_name": job.binary_path.name,
        "function_id": "",
        "original_function_name": "",
        "function_entry": "",
        "error_type": error_type,
        "message": message,
        "logged_at": utc_now(),
    }
    with job.errors_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def format_log(command: list[str], started_at: str, finished_at: str, returncode: int | None, stdout: str, stderr: str) -> str:
    return "\n".join(
        [
            f"started_at={started_at}",
            f"finished_at={finished_at}",
            f"returncode={returncode}",
            "command=" + " ".join(command),
            "",
            "=== stdout ===",
            stdout,
            "",
            "=== stderr ===",
            stderr,
            "",
        ]
    )


def write_text(path: str | Path, text: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_process_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
