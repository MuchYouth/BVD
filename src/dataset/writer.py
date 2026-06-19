"""Dataset writer for LLMDFA-primary records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from src.dataset.leakage_check import check_model_input
from src.dataset.schema import DatasetRecord


def build_dataset_record(
    llmdfa_record: dict[str, Any],
    *,
    conversion: dict[str, Any],
    metadata: dict[str, Any],
    ghidra_evidence: dict[str, Any] | None = None,
) -> DatasetRecord:
    """Build a dataset record with LLMDFA analysis as the primary result."""

    model_input = build_model_input(llmdfa_record, conversion=conversion)
    source_filename = Path(str(metadata.get("source_path", ""))).name
    leakage_result = check_model_input(
        model_input,
        source_filename=source_filename,
        original_function_name=str(conversion.get("original_function_name", "")),
    )
    warnings = list(
        dict.fromkeys(
            [
                *list(llmdfa_record.get("warnings", [])),
                *list(conversion.get("warnings", [])),
                *leakage_result.warnings,
            ]
        )
    )
    function_id = str(conversion.get("function_id") or llmdfa_record.get("function_id") or "")
    sample_id = str(conversion.get("original_sample_id") or metadata.get("sample_id") or "")

    return DatasetRecord(
        record_id=make_record_id(sample_id, function_id, str(llmdfa_record.get("record_id", ""))),
        sample_id=sample_id,
        cwe=str(metadata.get("cwe", "")),
        variant=str(metadata.get("variant", "")),
        binary_info={
            "binary_path": metadata.get("binary_path", ""),
            "sha256": metadata.get("sha256", ""),
            "opt_level": metadata.get("opt_level", ""),
        },
        function_id=function_id,
        llmdfa_result=llmdfa_result_to_metadata(llmdfa_record),
        ghidra_evidence=ghidra_evidence or {},
        analysis_mode="llmdfa_primary",
        metadata={
            **metadata,
            "llmdfa_record_id": llmdfa_record.get("record_id", ""),
            "llmdfa_source_file": llmdfa_record.get("source_file", ""),
            "converted_sample_id": conversion.get("sample_id", ""),
            "converted_source_path": conversion.get("source_path", ""),
            "original_function_name": conversion.get("original_function_name", ""),
            "function_entry": conversion.get("function_entry", ""),
        },
        model_input=model_input,
        leakage_check=leakage_result,
        warnings=warnings,
    )


def build_model_input(llmdfa_record: dict[str, Any], *, conversion: dict[str, Any]) -> dict[str, Any]:
    """Build model input from anonymized LLMDFA output only."""

    return {
        "function_id": str(conversion.get("function_id") or llmdfa_record.get("function_id") or ""),
        "llmdfa": {
            "source_sink_result": llmdfa_record.get("source_sink_result", {}),
            "dataflow_result": llmdfa_record.get("dataflow_result", {}),
            "path_validation_result": llmdfa_record.get("path_validation_result", {}),
        },
    }


def llmdfa_result_to_metadata(llmdfa_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": llmdfa_record.get("record_id", ""),
        "source_file": llmdfa_record.get("source_file", ""),
        "source_sink_result": llmdfa_record.get("source_sink_result", {}),
        "dataflow_result": llmdfa_record.get("dataflow_result", {}),
        "path_validation_result": llmdfa_record.get("path_validation_result", {}),
        "raw_output": llmdfa_record.get("raw_output", {}),
        "warnings": llmdfa_record.get("warnings", []),
    }


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any] | DatasetRecord], *, append: bool = False) -> int:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    count = 0
    with output_path.open(mode, encoding="utf-8") as handle:
        for record in records:
            payload = record.to_dict() if isinstance(record, DatasetRecord) else record
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            count += 1
    return count


def make_record_id(*parts: str) -> str:
    digest = hashlib.sha1(":".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"record_{digest}"

