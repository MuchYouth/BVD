"""Dataset writer for trace candidates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from src.analysis.source_sink import SinkCandidate, SourceCandidate
from src.analysis.trace_builder import TraceCandidate
from src.dataset.leakage_check import check_model_input
from src.dataset.schema import DatasetRecord
from src.pcode.schema import FunctionPcode


def build_dataset_record(
    trace: TraceCandidate,
    *,
    function: FunctionPcode,
    metadata: dict[str, Any],
    llm_review: dict[str, Any] | None = None,
) -> DatasetRecord:
    """Build a dataset record while keeping leakage-prone fields in metadata."""

    source_filename = Path(str(metadata.get("source_path", ""))).name
    model_input = build_model_input(trace)
    leakage_result = check_model_input(
        model_input,
        source_filename=source_filename,
        original_function_name=function.original_function_name,
    )
    warnings = list(dict.fromkeys([*trace.warnings, *leakage_result.warnings]))
    record_id = make_record_id(trace.sample_id, trace.function_id, trace.sink.sink_location, trace.reason)

    return DatasetRecord(
        record_id=record_id,
        sample_id=trace.sample_id,
        cwe=str(metadata.get("cwe", trace.analysis_cwe)),
        variant=str(metadata.get("variant", "")),
        binary_info={
            "binary_path": metadata.get("binary_path", ""),
            "sha256": metadata.get("sha256", ""),
            "opt_level": metadata.get("opt_level", ""),
        },
        function_id=trace.function_id,
        source_candidate=candidate_to_dict(trace.source),
        sink_candidate=candidate_to_dict(trace.sink),
        trace_candidate=trace_to_metadata_dict(trace, llm_review=llm_review),
        analysis_mode=trace.analysis_mode,
        metadata={
            **metadata,
            "original_function_name": function.original_function_name,
            "function_entry": function.function_entry,
            "llm_review": llm_review or {},
        },
        model_input=model_input,
        leakage_check=leakage_result,
        warnings=warnings,
    )


def build_model_input(trace: TraceCandidate) -> dict[str, Any]:
    """Build model input without CWE, variant, source path, or original symbols."""

    return {
        "function_id": trace.function_id,
        "source": {
            "source_type": trace.source.source_type,
            "source_location": trace.source.source_location,
            "source_varnodes": trace.source.source_varnodes,
            "confidence": trace.source.confidence,
        },
        "sink": {
            "sink_type": trace.sink.sink_type,
            "sink_location": trace.sink.sink_location,
            "sink_varnodes": trace.sink.sink_varnodes,
            "argument_indices": trace.sink.argument_indices,
            "confidence": trace.sink.confidence,
        },
        "trace": {
            "path_found": trace.path_found,
            "trace_ops": trace.trace_ops,
            "reason": trace.reason,
            "analysis_mode": trace.analysis_mode,
            "trace_type": trace.trace_type,
        },
    }


def candidate_to_dict(candidate: SourceCandidate | SinkCandidate) -> dict[str, Any]:
    return asdict(candidate)


def trace_to_metadata_dict(trace: TraceCandidate, *, llm_review: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "path_found": trace.path_found,
        "trace_ops": trace.trace_ops,
        "reason": trace.reason,
        "analysis_mode": trace.analysis_mode,
        "analysis_cwe": trace.analysis_cwe,
        "trace_type": trace.trace_type,
        "warnings": trace.warnings,
        "llm_review": llm_review or {},
    }


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any] | DatasetRecord], *, append: bool = False) -> int:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    count = 0
    with output_path.open(mode, encoding="utf-8") as handle:
        for record in records:
            if isinstance(record, DatasetRecord):
                payload = record.to_dict()
            else:
                payload = record
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            count += 1
    return count


def make_record_id(*parts: str) -> str:
    digest = hashlib.sha1(":".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"record_{digest}"
