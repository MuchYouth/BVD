"""Load Ghidra P-code and callsite JSONL as evidence only."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from src.ghidra_evidence.schema import FunctionEvidence, SampleEvidence
from src.pcode.parser import load_callsites_jsonl, load_pcode_jsonl
from src.pcode.schema import FunctionPcode, JsonlParseError


def load_sample_evidence(
    pcode_path: str | Path,
    callsites_path: str | Path,
    *,
    sample_id: str = "",
    function_id_by_entry: dict[str, str] | None = None,
) -> SampleEvidence:
    pcode_result = load_pcode_jsonl(pcode_path)
    callsite_result = load_callsites_jsonl(callsites_path)
    functions = group_evidence_records(
        pcode_result.records,
        callsite_result.records,
        function_id_by_entry=function_id_by_entry or {},
    )
    errors = [*_parse_errors_to_dicts(pcode_result.errors), *_parse_errors_to_dicts(callsite_result.errors)]
    warnings: list[str] = []
    if pcode_result.errors:
        warnings.append("pcode_parse_errors_present")
    if callsite_result.errors:
        warnings.append("callsite_parse_errors_present")
    return SampleEvidence(
        sample_id=sample_id or infer_sample_id(functions, pcode_path),
        pcode_path=Path(pcode_path).as_posix(),
        callsites_path=Path(callsites_path).as_posix(),
        functions=functions,
        parser_errors=errors,
        warnings=warnings,
    )


def group_evidence_records(
    pcode_records: Iterable,
    callsite_records: Iterable,
    *,
    function_id_by_entry: dict[str, str] | None = None,
) -> list[FunctionEvidence]:
    from src.pcode.parser import group_records_by_function

    grouped: list[FunctionPcode] = group_records_by_function(pcode_records, callsite_records)
    mapping = function_id_by_entry or {}
    evidence: list[FunctionEvidence] = []
    for function in grouped:
        function_id = mapping.get(function.function_entry, function.function_id)
        evidence.append(
            FunctionEvidence(
                sample_id=function.sample_id,
                function_id=function_id,
                original_function_name=function.original_function_name,
                function_entry=function.function_entry,
                pcode_ops=[op.to_dict() for op in function.ops],
                callsites=[callsite.to_dict() for callsite in function.callsites],
            )
        )
    return evidence


def evidence_paths_for_metadata(pcode_root: str | Path, metadata: dict) -> tuple[Path, Path]:
    sample_id = str(metadata.get("sample_id", ""))
    cwe = str(metadata.get("cwe", ""))
    variant = str(metadata.get("variant", ""))
    opt_level = str(metadata.get("opt_level", ""))
    sample_dir = Path(pcode_root) / cwe / variant / opt_level
    return sample_dir / f"{sample_id}.pcode.jsonl", sample_dir / f"{sample_id}.callsites.jsonl"


def _parse_errors_to_dicts(errors: Iterable[JsonlParseError]) -> list[dict[str, object]]:
    return [
        {
            "path": error.path,
            "line_number": error.line_number,
            "message": error.message,
            "raw_line": error.raw_line,
        }
        for error in errors
    ]


def infer_sample_id(functions: list[FunctionEvidence], pcode_path: str | Path) -> str:
    if functions:
        return functions[0].sample_id
    return Path(pcode_path).name.removesuffix(".pcode.jsonl")

