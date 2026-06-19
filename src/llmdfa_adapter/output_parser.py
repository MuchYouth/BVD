"""Parse upstream LLMDFA outputs into a stable wrapper schema."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


DEFAULT_OUTPUT_ROOT = Path("data/llmdfa_outputs")
DEFAULT_PARSED_PATH = Path("data/llmdfa_outputs/parsed_results.jsonl")


@dataclass(frozen=True)
class ParsedLLMDFARecord:
    record_id: str
    source_file: str
    source_sink_result: dict[str, Any] = field(default_factory=dict)
    dataflow_result: dict[str, Any] = field(default_factory=dict)
    path_validation_result: dict[str, Any] = field(default_factory=dict)
    raw_output: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "source_file": self.source_file,
            "source_sink_result": self.source_sink_result,
            "dataflow_result": self.dataflow_result,
            "path_validation_result": self.path_validation_result,
            "raw_output": self.raw_output,
            "warnings": self.warnings,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="LLMDFA output/log root to parse.")
    parser.add_argument("--parsed-path", default=str(DEFAULT_PARSED_PATH), help="Output JSONL path for parsed records.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = parse_llmdfa_output(Path(args.output_root))
    written = write_jsonl(Path(args.parsed_path), [record.to_dict() for record in records])
    print(json.dumps({"records": len(records), "parsed_path": args.parsed_path, "written": written}, indent=2, sort_keys=True))
    return 0


def parse_llmdfa_output(output_root: Path = DEFAULT_OUTPUT_ROOT) -> list[ParsedLLMDFARecord]:
    """Parse known LLMDFA JSON reports while preserving raw outputs.

    Upstream LLMDFA writes per-case `report_summary.json` files plus additional
    logs under `log/{model}/{mode}/{case}`. Its internal report structure is not
    currently a stable public dataset schema, so this parser separates the parts
    we can identify and keeps the original JSON payload intact.
    """

    records: list[ParsedLLMDFARecord] = []
    if not output_root.exists():
        return records

    for path in sorted(output_root.rglob("*.json")):
        if should_skip_json(path):
            continue
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        records.append(record_from_json(path, data))
    return records


def should_skip_json(path: Path) -> bool:
    return path.name in {"run_metadata.json", "parsed_results.json"}


def record_from_json(path: Path, data: dict[str, Any]) -> ParsedLLMDFARecord:
    warnings: list[str] = []
    source_sink_result = extract_source_sink_result(data, warnings)
    dataflow_result = extract_dataflow_result(data, warnings)
    path_validation_result = extract_path_validation_result(data, warnings)
    return ParsedLLMDFARecord(
        record_id=f"llmdfa_{stable_id(path.as_posix())}",
        source_file=infer_source_file(path, data),
        source_sink_result=source_sink_result,
        dataflow_result=dataflow_result,
        path_validation_result=path_validation_result,
        raw_output=data,
        warnings=warnings,
    )


def extract_source_sink_result(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("sources", "sinks", "srcs", "source_sink_result"):
        if key in data:
            result[key] = data[key]
    if not result:
        warnings.append("source_sink_result_not_found")
    return result


def extract_dataflow_result(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("bug_reports", "bug_candidates", "dataflow_result", "analysis_result"):
        if key in data:
            result[key] = data[key]
    if "input_token_cost" in data:
        result["input_token_cost"] = data["input_token_cost"]
    if "output_token_cost" in data:
        result["output_token_cost"] = data["output_token_cost"]
    if not result:
        warnings.append("dataflow_result_not_found")
    return result


def extract_path_validation_result(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("path_validation_result", "validation_result", "ground_truth"):
        if key in data:
            result[key] = data[key]
    if not result:
        warnings.append("path_validation_result_not_found")
    return result


def infer_source_file(path: Path, data: dict[str, Any]) -> str:
    for key in ("source_file", "java_file_path", "input_file"):
        if key in data:
            return str(data[key])
    return path.parent.name


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
    return count


def stable_id(value: str) -> str:
    import hashlib

    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:16]


if __name__ == "__main__":
    raise SystemExit(main())
