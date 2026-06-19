"""Wrapper for invoking upstream LLMDFA without editing its source tree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_LLMDFA_ROOT = Path("external/LLMDFA")
DEFAULT_INPUT_MANIFEST = Path("data/llmdfa_inputs/manifest.jsonl")
DEFAULT_OUTPUT_ROOT = Path("data/llmdfa_outputs")


@dataclass(frozen=True)
class LLMDFARunResult:
    llmdfa_root: Path
    input_manifest: Path
    output_root: Path
    command: list[str]
    returncode: int | None
    stdout_path: Path
    stderr_path: Path
    metadata_path: Path
    status: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "llmdfa_root": self.llmdfa_root.as_posix(),
            "input_manifest": self.input_manifest.as_posix(),
            "output_root": self.output_root.as_posix(),
            "command": self.command,
            "returncode": self.returncode,
            "stdout_path": self.stdout_path.as_posix(),
            "stderr_path": self.stderr_path.as_posix(),
            "metadata_path": self.metadata_path.as_posix(),
            "status": self.status,
            "warnings": self.warnings,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llmdfa-root", default=str(DEFAULT_LLMDFA_ROOT), help="Path to external LLMDFA checkout.")
    parser.add_argument("--input-manifest", default=str(DEFAULT_INPUT_MANIFEST), help="Manifest from input_converter.py.")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Directory for wrapper logs and parsed outputs.")
    parser.add_argument("--bug-type", choices=["osci", "xss", "dbz"], default="osci", help="Upstream LLMDFA bug type.")
    parser.add_argument("--model-name", default="gpt-4o-mini", help="Upstream LLMDFA model name.")
    parser.add_argument("--analysis-mode", choices=["single", "all"], default="single", help="Upstream LLMDFA analysis mode.")
    parser.add_argument("--solving-refine-number", type=int, default=3, help="Upstream solver refine count.")
    parser.add_argument("--syn-parser", action="store_true", help="Pass -syn-parser to upstream LLMDFA.")
    parser.add_argument("--fscot", action="store_true", help="Pass -fscot to upstream LLMDFA.")
    parser.add_argument("--syn-solver", action="store_true", help="Pass -syn-solver to upstream LLMDFA.")
    parser.add_argument("--dry-run", action="store_true", help="Write metadata without invoking LLMDFA.")
    parser.add_argument(
        "--allow-upstream-benchmark-run",
        action="store_true",
        help="Run upstream demo benchmark even though converted C/C++ inputs are not consumed by unmodified LLMDFA.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_llmdfa(
        llmdfa_root=Path(args.llmdfa_root),
        input_manifest=Path(args.input_manifest),
        output_root=Path(args.output_root),
        bug_type=args.bug_type,
        model_name=args.model_name,
        analysis_mode=args.analysis_mode,
        solving_refine_number=args.solving_refine_number,
        syn_parser=args.syn_parser,
        fscot=args.fscot,
        syn_solver=args.syn_solver,
        dry_run=args.dry_run,
        allow_upstream_benchmark_run=args.allow_upstream_benchmark_run,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status in {"dry_run", "completed", "blocked_needs_upstream_patch"} else 1


def run_llmdfa(
    *,
    llmdfa_root: Path = DEFAULT_LLMDFA_ROOT,
    input_manifest: Path = DEFAULT_INPUT_MANIFEST,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    bug_type: str = "osci",
    model_name: str = "gpt-4o-mini",
    analysis_mode: str = "single",
    solving_refine_number: int = 3,
    syn_parser: bool = True,
    fscot: bool = True,
    syn_solver: bool = True,
    dry_run: bool = False,
    allow_upstream_benchmark_run: bool = False,
) -> LLMDFARunResult:
    """Invoke upstream entry point when possible and record wrapper metadata.

    Unmodified LLMDFA currently expects Java Juliet benchmark directories under
    external/LLMDFA/benchmark. Converted decompiled C/C++ files are therefore
    not consumed unless upstream gains an arbitrary-input/C/C++ entry point.
    """

    output_root.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    metadata_path = run_dir / "run_metadata.json"
    command = build_command(
        bug_type=bug_type,
        model_name=model_name,
        analysis_mode=analysis_mode,
        solving_refine_number=solving_refine_number,
        syn_parser=syn_parser,
        fscot=fscot,
        syn_solver=syn_solver,
    )
    warnings = compatibility_warnings(llmdfa_root, input_manifest)

    if dry_run:
        return write_result(
            LLMDFARunResult(
                llmdfa_root=llmdfa_root,
                input_manifest=input_manifest,
                output_root=run_dir,
                command=command,
                returncode=None,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                metadata_path=metadata_path,
                status="dry_run",
                warnings=warnings,
            )
        )

    if not llmdfa_root.exists():
        return write_result(
            LLMDFARunResult(
                llmdfa_root=llmdfa_root,
                input_manifest=input_manifest,
                output_root=run_dir,
                command=command,
                returncode=None,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                metadata_path=metadata_path,
                status="missing_llmdfa_checkout",
                warnings=warnings,
            )
        )

    if not allow_upstream_benchmark_run:
        return write_result(
            LLMDFARunResult(
                llmdfa_root=llmdfa_root,
                input_manifest=input_manifest,
                output_root=run_dir,
                command=command,
                returncode=None,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                metadata_path=metadata_path,
                status="blocked_needs_upstream_patch",
                warnings=[
                    *warnings,
                    "unmodified_llmdfa_does_not_accept_converted_c_cpp_manifest",
                    "run_with_allow_upstream_benchmark_run_only_for_upstream_demo_validation",
                ],
            )
        )

    env = os.environ.copy()
    completed = subprocess.run(
        command,
        cwd=llmdfa_root / "src",
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    status = "completed" if completed.returncode == 0 else "failed"
    return write_result(
        LLMDFARunResult(
            llmdfa_root=llmdfa_root,
            input_manifest=input_manifest,
            output_root=run_dir,
            command=command,
            returncode=completed.returncode,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            metadata_path=metadata_path,
            status=status,
            warnings=warnings,
        )
    )


def build_command(
    *,
    bug_type: str,
    model_name: str,
    analysis_mode: str,
    solving_refine_number: int,
    syn_parser: bool,
    fscot: bool,
    syn_solver: bool,
) -> list[str]:
    command = [
        "python",
        "run_llmdfa.py",
        "--bug-type",
        bug_type,
        "--model-name",
        model_name,
        "--solving-refine-number",
        str(solving_refine_number),
        "--analysis-mode",
        analysis_mode,
    ]
    if syn_parser:
        command.append("-syn-parser")
    if fscot:
        command.append("-fscot")
    if syn_solver:
        command.append("-syn-solver")
    return command


def compatibility_warnings(llmdfa_root: Path, input_manifest: Path) -> list[str]:
    warnings: list[str] = []
    if not input_manifest.exists():
        warnings.append("input_manifest_missing")
    if not (llmdfa_root / "src" / "run_llmdfa.py").exists():
        warnings.append("upstream_entrypoint_missing")
    warnings.append("upstream_entrypoint_currently_uses_java_benchmark_layout")
    warnings.append("converted_decompiled_c_cpp_inputs_require_upstream_arbitrary_input_patch")
    return warnings


def write_result(result: LLMDFARunResult) -> LLMDFARunResult:
    result.metadata_path.parent.mkdir(parents=True, exist_ok=True)
    result.metadata_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
