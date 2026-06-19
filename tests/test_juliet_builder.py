from pathlib import Path

from src.juliet.builder import (
    command_for_job,
    create_build_jobs,
    metadata_record,
    run_build_job,
)


def write_source(path: Path, text: str = "int main(void) { return 0; }\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def manifest_record(source_path: str, *, manifest_id: str = "sample", language: str = "c") -> dict:
    return {
        "manifest_id": manifest_id,
        "cwe": "CWE78",
        "source_path": source_path,
        "language": language,
        "build_candidate": True,
    }


def base_tree(tmp_path: Path) -> Path:
    root = tmp_path / "juliet"
    support = root / "C" / "testcasesupport"
    write_source(support / "io.c")
    write_source(support / "std_thread.c")
    return root


def build_jobs(tmp_path: Path, records: list[dict]) -> list:
    return create_build_jobs(
        records,
        juliet_root=tmp_path / "juliet",
        binaries_dir=tmp_path / "binaries",
        juliet_config={
            "compiler": {"c": "gcc", "cpp": "g++"},
            "variants": ["bad", "good"],
            "opt_levels": ["O0"],
        },
        timeout_sec=60,
    )


def test_build_command_includes_debug_support_sources_and_metadata(tmp_path: Path) -> None:
    root = base_tree(tmp_path)
    rel = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_01.c"
    source = write_source(root / rel)

    jobs = build_jobs(tmp_path, [manifest_record(rel, manifest_id="cwe78_01")])
    bad_job = next(job for job in jobs if job.variant == "bad")
    command = command_for_job(bad_job)

    assert "-g" in bad_job.compile_flags
    assert f"-I{root / 'C' / 'testcasesupport'}" in bad_job.compile_flags
    assert str(source) in command
    assert str(root / "C" / "testcasesupport" / "io.c") in command
    assert str(root / "C" / "testcasesupport" / "std_thread.c") in command
    assert "-lpthread" in command
    assert "-lm" in command

    record = metadata_record(
        bad_job,
        started_at="start",
        finished_at="finish",
        compile_success=True,
        compile_stdout="",
        compile_stderr="",
        sha256="binaryhash",
        compiler_version="gcc test",
    )

    assert record["full_command"] == command
    assert record["compiler_version"] == "gcc test"
    assert record["debug_symbols"] is True
    assert record["build_strategy"] == "manifest_family"
    assert record["source_sha256"]
    assert record["source_hashes"][source.as_posix()]


def test_companion_family_sources_are_grouped_from_entrypoint(tmp_path: Path) -> None:
    root = base_tree(tmp_path)
    rel_a = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_22a.c"
    rel_b = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_22b.c"
    source_a = write_source(root / rel_a)
    source_b = write_source(root / rel_b)

    jobs = build_jobs(
        tmp_path,
        [
            manifest_record(rel_a, manifest_id="cwe78_22a"),
            manifest_record(rel_b, manifest_id="cwe78_22b"),
        ],
    )

    entry_job = next(job for job in jobs if job.sample_id == "cwe78_22a" and job.variant == "bad")
    companion_job = next(job for job in jobs if job.sample_id == "cwe78_22b" and job.variant == "bad")

    assert entry_job.source_paths == [source_a, source_b]
    assert companion_job.skip_reason == "companion_source_not_entrypoint"


def test_cpp_companion_family_uses_cpp_compiler(tmp_path: Path) -> None:
    root = base_tree(tmp_path)
    rel_a = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_81a.cpp"
    rel_bad = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_81_bad.cpp"
    rel_good = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_81_goodG2B.cpp"
    source_a = write_source(root / rel_a)
    source_bad = write_source(root / rel_bad)
    source_good = write_source(root / rel_good)

    jobs = build_jobs(tmp_path, [manifest_record(rel_a, manifest_id="cwe78_81a", language="cpp")])
    job = next(job for job in jobs if job.variant == "bad")

    assert job.compiler == "g++"
    assert job.source_paths == [source_bad, source_good, source_a]


def test_linux_unsupported_sources_are_skipped_with_reason(tmp_path: Path) -> None:
    root = base_tree(tmp_path)
    rel = "C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_w32_01.c"
    write_source(root / rel)

    jobs = build_jobs(tmp_path, [manifest_record(rel, manifest_id="cwe78_w32")])
    job = next(job for job in jobs if job.variant == "bad")
    result = run_build_job(job, resume=False, force=True)

    assert job.skip_reason == "platform_unsupported_linux"
    assert result["skipped"] is True
    assert result["skip_reason"] == "platform_unsupported_linux"
    assert result["compile_success"] is False
