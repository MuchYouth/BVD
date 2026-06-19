"""Juliet manifest-based build manager."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.juliet.discovery import load_config, resolve_cwe_scope

LOGGER = logging.getLogger(__name__)

VARIANT_DEFINES = {
    "bad": ["-DINCLUDEMAIN", "-DOMITGOOD"],
    "good": ["-DINCLUDEMAIN", "-DOMITBAD"],
}
LINUX_UNSUPPORTED_NAME_PARTS = ("w32", "wchar_t")
BUILD_STRATEGY = "manifest_family"
DEBUG_FLAG = "-g"
DEFAULT_LINK_FLAGS = ["-lpthread", "-lm"]
SUPPORT_SOURCE_NAMES = ("io.c", "std_thread.c")
TESTCASE_SUPPORT_DIR = Path("C/testcasesupport")
NON_ENTRYPOINT_COMPANION_RE = re.compile(r"_[0-9]{2,}[b-z](?:_|$)", re.IGNORECASE)


@dataclass(frozen=True)
class BuildJob:
    manifest_record: dict[str, Any]
    sample_id: str
    cwe: str
    variant: str
    opt_level: str
    source_path: Path
    source_paths: list[Path]
    support_source_paths: list[Path]
    include_dirs: list[Path]
    binary_path: Path
    compiler: str
    compile_flags: list[str]
    link_flags: list[str]
    timeout_sec: int
    skip_reason: str = ""


@dataclass(frozen=True)
class BuildSummary:
    planned: int
    attempted: int
    succeeded: int
    failed: int
    skipped: int
    dry_run: bool
    metadata_path: Path
    status_path: Path


def run_build(
    config_path: str | Path,
    *,
    cli_cwes: Iterable[str] | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    resume: bool | None = None,
    force: bool | None = None,
    jobs: int | None = None,
) -> BuildSummary:
    """Run the manifest-based Juliet build stage."""

    config = load_config(config_path)
    juliet_config = config.get("juliet", {})
    dataset_config = config.get("dataset", {})
    build_config = juliet_config.get("build", {})

    manifest_path = Path(juliet_config.get("manifest_path", "data/manifests/juliet_manifest.jsonl"))
    juliet_root = Path(juliet_config.get("root", "data/raw_juliet"))
    binaries_dir = Path(dataset_config.get("binaries_dir", "data/binaries"))
    metadata_path = binaries_dir / "build_metadata.jsonl"
    status_path = manifest_path.parent / "pipeline_status.jsonl"

    effective_resume = bool(build_config.get("resume", True)) if resume is None else resume
    effective_force = bool(build_config.get("force", False)) if force is None else force
    effective_jobs = int(jobs or build_config.get("jobs", 1) or 1)
    timeout_sec = int(build_config.get("timeout_sec", 60))

    cwe_scope = resolve_cwe_scope(config, cli_cwes)
    manifest_records = read_manifest(manifest_path)
    selected_records = select_build_candidates(manifest_records, cwe_scope=cwe_scope, limit=limit)
    build_jobs = create_build_jobs(
        selected_records,
        juliet_root=juliet_root,
        binaries_dir=binaries_dir,
        juliet_config=juliet_config,
        timeout_sec=timeout_sec,
    )
    validate_compilers(build_jobs)

    LOGGER.info("Selected %s manifest records and planned %s build jobs", len(selected_records), len(build_jobs))
    if dry_run:
        for job in build_jobs:
            if job.skip_reason:
                LOGGER.info("DRY-RUN skip %s %s %s: %s", job.cwe, job.sample_id, job.variant, job.skip_reason)
            else:
                LOGGER.info("DRY-RUN %s", " ".join(command_for_job(job)))
        return BuildSummary(
            planned=len(build_jobs),
            attempted=0,
            succeeded=0,
            failed=0,
            skipped=0,
            dry_run=True,
            metadata_path=metadata_path,
            status_path=status_path,
        )

    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.parent.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    if effective_jobs > 1 and len(build_jobs) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_jobs) as executor:
            future_to_job = {
                executor.submit(run_build_job, job, resume=effective_resume, force=effective_force): job
                for job in build_jobs
            }
            for future in concurrent.futures.as_completed(future_to_job):
                results.append(future.result())
    else:
        for job in build_jobs:
            results.append(run_build_job(job, resume=effective_resume, force=effective_force))

    write_jsonl(metadata_path, results, append=True)
    write_jsonl(status_path, [status_record(result) for result in results], append=True)

    succeeded = sum(1 for result in results if result["compile_success"])
    skipped = sum(1 for result in results if result.get("skipped"))
    failed = sum(1 for result in results if not result["compile_success"] and not result.get("skipped"))
    attempted = len(results) - skipped

    LOGGER.info(
        "Build complete: planned=%s attempted=%s succeeded=%s failed=%s skipped=%s",
        len(build_jobs),
        attempted,
        succeeded,
        failed,
        skipped,
    )
    return BuildSummary(
        planned=len(build_jobs),
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        dry_run=False,
        metadata_path=metadata_path,
        status_path=status_path,
    )


def read_manifest(path: str | Path) -> list[dict[str, Any]]:
    manifest_path = Path(path)
    if not manifest_path.exists():
        LOGGER.warning("Manifest file does not exist: %s", manifest_path)
        return []

    records: list[dict[str, Any]] = []
    with manifest_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                LOGGER.warning("Skipping invalid manifest JSON at %s:%s: %s", manifest_path, line_number, exc)
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def select_build_candidates(
    records: Iterable[dict[str, Any]],
    *,
    cwe_scope: set[str] | None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for record in records:
        if record.get("build_candidate") is not True:
            continue
        cwe = str(record.get("cwe", ""))
        if cwe_scope is not None and cwe not in cwe_scope:
            continue
        selected.append(record)
        if limit is not None and len(selected) >= limit:
            break
    return selected


def create_build_jobs(
    records: Iterable[dict[str, Any]],
    *,
    juliet_root: Path,
    binaries_dir: Path,
    juliet_config: dict[str, Any],
    timeout_sec: int,
) -> list[BuildJob]:
    jobs: list[BuildJob] = []
    compilers = juliet_config.get("compiler", {})
    variants = juliet_config.get("variants", ["bad", "good"])
    opt_levels = juliet_config.get("opt_levels", ["O0"])
    support_dir = juliet_root / TESTCASE_SUPPORT_DIR
    include_dirs = [support_dir]
    support_source_paths = [support_dir / name for name in SUPPORT_SOURCE_NAMES if (support_dir / name).exists()]

    for record in records:
        cwe = str(record["cwe"])
        sample_id = str(record.get("sample_id") or record["manifest_id"])
        source_path = resolve_source_path(juliet_root, str(record["source_path"]))
        skip_reason = skip_reason_for_source(source_path)
        source_paths = [source_path] if skip_reason else companion_source_paths(source_path)
        if not skip_reason and not is_entrypoint_source(source_path):
            skip_reason = "companion_source_not_entrypoint"
        language = language_for_sources(source_paths, str(record.get("language", "")).lower())
        compiler = str(compilers.get(language, "g++" if language == "cpp" else "gcc"))

        for variant in variants:
            if variant not in VARIANT_DEFINES:
                LOGGER.warning("Skipping unsupported build variant %s for %s", variant, sample_id)
                continue
            for opt_level in opt_levels:
                opt = normalize_opt_level(str(opt_level))
                compile_flags = [f"-{opt}", DEBUG_FLAG, *VARIANT_DEFINES[variant], *include_flags(include_dirs)]
                binary_path = binaries_dir / cwe / variant / opt / f"{sample_id}.out"
                jobs.append(
                    BuildJob(
                        manifest_record=record,
                        sample_id=sample_id,
                        cwe=cwe,
                        variant=variant,
                        opt_level=opt,
                        source_path=source_path,
                        source_paths=source_paths,
                        support_source_paths=support_source_paths,
                        include_dirs=include_dirs,
                        binary_path=binary_path,
                        compiler=compiler,
                        compile_flags=compile_flags,
                        link_flags=DEFAULT_LINK_FLAGS.copy(),
                        timeout_sec=timeout_sec,
                        skip_reason=skip_reason,
                    )
                )
    return jobs


def run_build_job(job: BuildJob, *, resume: bool, force: bool) -> dict[str, Any]:
    started_at = utc_now()
    compiler_version = get_compiler_version(job.compiler)

    if job.skip_reason:
        return metadata_record(
            job,
            started_at=started_at,
            finished_at=utc_now(),
            compile_success=False,
            compile_stdout="",
            compile_stderr="",
            sha256="",
            returncode=None,
            skipped=True,
            skip_reason=job.skip_reason,
            compiler_version=compiler_version,
        )

    if resume and not force and job.binary_path.exists():
        sha256 = sha256_file(job.binary_path)
        return metadata_record(
            job,
            started_at=started_at,
            finished_at=utc_now(),
            compile_success=True,
            compile_stdout="skipped: existing successful binary reused by --resume",
            compile_stderr="",
            sha256=sha256,
            skipped=True,
            skip_reason="resume_existing_binary",
            compiler_version=compiler_version,
        )

    command = command_for_job(job)
    job.binary_path.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.info("Compiling %s %s %s -> %s", job.cwe, job.variant, job.opt_level, job.binary_path)

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=job.timeout_sec,
        )
        compile_success = completed.returncode == 0 and job.binary_path.exists()
        stderr = completed.stderr
        if compile_success and not binary_has_debug_info(job.binary_path):
            compile_success = False
            stderr = f"{stderr.rstrip()}\ncompiled binary missing debug info".strip()
        if not compile_success:
            stderr = append_support_todo(stderr)
        return metadata_record(
            job,
            started_at=started_at,
            finished_at=utc_now(),
            compile_success=compile_success,
            compile_stdout=completed.stdout,
            compile_stderr=stderr,
            sha256=sha256_file(job.binary_path) if compile_success else "",
            returncode=completed.returncode,
            skipped=False,
            compiler_version=compiler_version,
        )
    except subprocess.TimeoutExpired as exc:
        return metadata_record(
            job,
            started_at=started_at,
            finished_at=utc_now(),
            compile_success=False,
            compile_stdout=decode_process_text(exc.stdout),
            compile_stderr=append_support_todo(f"compile timeout after {job.timeout_sec}s\n{decode_process_text(exc.stderr)}"),
            sha256="",
            returncode=None,
            skipped=False,
            compiler_version=compiler_version,
        )
    except OSError as exc:
        return metadata_record(
            job,
            started_at=started_at,
            finished_at=utc_now(),
            compile_success=False,
            compile_stdout="",
            compile_stderr=append_support_todo(str(exc)),
            sha256="",
            returncode=None,
            skipped=False,
            compiler_version=compiler_version,
        )


def command_for_job(job: BuildJob) -> list[str]:
    return [
        job.compiler,
        *[str(path) for path in job.source_paths],
        *[str(path) for path in job.support_source_paths],
        *job.compile_flags,
        *job.link_flags,
        "-o",
        str(job.binary_path),
    ]


def metadata_record(
    job: BuildJob,
    *,
    started_at: str,
    finished_at: str,
    compile_success: bool,
    compile_stdout: str,
    compile_stderr: str,
    sha256: str,
    returncode: int | None = None,
    skipped: bool = False,
    skip_reason: str = "",
    compiler_version: str = "",
) -> dict[str, Any]:
    command = command_for_job(job) if not job.skip_reason else []
    return {
        "sample_id": job.sample_id,
        "manifest_id": job.manifest_record.get("manifest_id", ""),
        "cwe": job.cwe,
        "variant": job.variant,
        "source_path": job.manifest_record.get("source_path", str(job.source_path)),
        "source_paths": [path.as_posix() for path in job.source_paths],
        "source_sha256": combined_sha256(job.source_paths),
        "source_hashes": {path.as_posix(): sha256_file(path) for path in job.source_paths if path.exists()},
        "support_source_paths": [path.as_posix() for path in job.support_source_paths],
        "binary_path": job.binary_path.as_posix(),
        "compiler": job.compiler,
        "compiler_version": compiler_version,
        "opt_level": job.opt_level,
        "compile_flags": job.compile_flags,
        "link_flags": job.link_flags,
        "full_command": command,
        "build_strategy": BUILD_STRATEGY,
        "debug_symbols": True,
        "compile_success": compile_success,
        "compile_stdout": compile_stdout,
        "compile_stderr": compile_stderr,
        "sha256": sha256,
        "started_at": started_at,
        "finished_at": finished_at,
        "returncode": returncode,
        "skipped": skipped,
        "skip_reason": skip_reason,
    }


def status_record(result: dict[str, Any]) -> dict[str, Any]:
    build_status = "success" if result["compile_success"] else "failed"
    if result.get("skipped"):
        build_status = "skipped"
    return {
        "stage": "build",
        "sample_id": result["sample_id"],
        "manifest_id": result["manifest_id"],
        "cwe": result["cwe"],
        "variant": result["variant"],
        "opt_level": result["opt_level"],
        "binary_path": result["binary_path"],
        "build_status": build_status,
        "skipped": result.get("skipped", False),
        "skip_reason": result.get("skip_reason", ""),
        "started_at": result["started_at"],
        "finished_at": result["finished_at"],
    }


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any]], *, append: bool = False) -> int:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    count = 0
    with output_path.open(mode, encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
    return count


def resolve_source_path(juliet_root: Path, source_path: str) -> Path:
    path = Path(source_path)
    return path if path.is_absolute() else juliet_root / path


def normalize_opt_level(opt_level: str) -> str:
    return opt_level[1:] if opt_level.startswith("-") else opt_level


def include_flags(include_dirs: Iterable[Path]) -> list[str]:
    return [f"-I{path}" for path in include_dirs]


def skip_reason_for_source(source_path: Path) -> str:
    name = source_path.name.lower()
    if any(part in name for part in LINUX_UNSUPPORTED_NAME_PARTS):
        return "platform_unsupported_linux"
    return ""


def is_entrypoint_source(source_path: Path) -> bool:
    if skip_reason_for_source(source_path):
        return False
    stem = source_path.stem
    if "_bad" in stem or "_good" in stem:
        return False
    return NON_ENTRYPOINT_COMPANION_RE.search(stem) is None


def companion_source_paths(source_path: Path) -> list[Path]:
    if not is_entrypoint_source(source_path):
        return [source_path]
    prefix = testcase_build_prefix(source_path)
    candidates = sorted(
        path
        for path in source_path.parent.glob(f"{prefix}*")
        if path.is_file()
        and path.suffix.lower() in {".c", ".cpp", ".cc", ".cxx"}
        and not skip_reason_for_source(path)
    )
    return candidates or [source_path]


def testcase_build_prefix(source_path: Path) -> str:
    stem = source_path.stem
    match = re.search(r"_[0-9]{2,}a$", stem, flags=re.IGNORECASE)
    if match:
        return stem[:-1]
    return stem


def language_for_sources(source_paths: Iterable[Path], fallback: str) -> str:
    if any(path.suffix.lower() in {".cpp", ".cc", ".cxx"} for path in source_paths):
        return "cpp"
    return fallback or "c"


def validate_compilers(jobs: Iterable[BuildJob]) -> None:
    for compiler in sorted({job.compiler for job in jobs if not job.skip_reason}):
        if shutil.which(compiler) is None:
            LOGGER.error("Compiler not found on PATH: %s", compiler)


def get_compiler_version(compiler: str) -> str:
    if not compiler or shutil.which(compiler) is None:
        return ""
    try:
        completed = subprocess.run(
            [compiler, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.splitlines()[0] if completed.stdout else ""


def combined_sha256(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    found = False
    for path in paths:
        if not path.exists():
            continue
        found = True
        digest.update(path.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest() if found else ""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_has_debug_info(path: str | Path) -> bool:
    needles = (b".debug_info", b".zdebug_info")
    overlap = max(len(needle) for needle in needles) - 1
    tail = b""
    try:
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                data = tail + chunk
                if any(needle in data for needle in needles):
                    return True
                tail = data[-overlap:]
    except OSError:
        return False
    return False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_process_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def append_support_todo(stderr: str) -> str:
    todo = (
        "\nTODO: If this Juliet family needs additional platform libraries, generated files, "
        "or a build rule not covered by manifest_family, extend src/juliet/builder.py."
    )
    return f"{stderr.rstrip()}{todo}" if stderr else todo.strip()
