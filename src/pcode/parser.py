"""Parsers for Ghidra P-code and callsite JSONL."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

from src.pcode.schema import CallsiteRecord, FunctionPcode, JsonlLoadResult, JsonlParseError, PcodeOpRecord

LOGGER = logging.getLogger(__name__)


def load_pcode_jsonl(path: str | Path) -> JsonlLoadResult:
    """Load P-code JSONL records.

    Broken lines are reported in `result.errors` with path and line number.
    """

    return _load_jsonl(path, PcodeOpRecord.from_dict)


def load_callsites_jsonl(path: str | Path) -> JsonlLoadResult:
    """Load callsite JSONL records."""

    return _load_jsonl(path, CallsiteRecord.from_dict)


def group_records_by_function(
    pcode_records: Iterable[PcodeOpRecord] | JsonlLoadResult,
    callsite_records: Iterable[CallsiteRecord] | JsonlLoadResult,
) -> list[FunctionPcode]:
    """Group P-code ops and callsites by sample/function entry/name."""

    pcode_list = _records(pcode_records)
    callsite_list = _records(callsite_records)
    grouped_ops: dict[tuple[str, str, str], list[PcodeOpRecord]] = defaultdict(list)
    grouped_callsites: dict[tuple[str, str, str], list[CallsiteRecord]] = defaultdict(list)

    for record in pcode_list:
        grouped_ops[_function_key(record.sample_id, record.function_entry, record.function_name)].append(record)
    for record in callsite_list:
        grouped_callsites[_function_key(record.sample_id, record.function_entry, record.function_name)].append(record)

    keys = sorted(set(grouped_ops) | set(grouped_callsites))
    functions: list[FunctionPcode] = []
    for index, key in enumerate(keys, start=1):
        sample_id, function_entry, function_name = key
        ops = sorted(grouped_ops.get(key, []), key=lambda record: record.op_seq)
        callsites = sorted(grouped_callsites.get(key, []), key=lambda record: record.call_address)
        functions.append(
            FunctionPcode(
                sample_id=sample_id,
                function_id=f"function_{index:04d}",
                original_function_name=function_name,
                function_entry=function_entry,
                ops=ops,
                callsites=callsites,
            )
        )
    return functions


def _load_jsonl(path: str | Path, factory: Callable[[dict[str, Any]], Any]) -> JsonlLoadResult:
    jsonl_path = Path(path)
    records: list[Any] = []
    errors: list[JsonlParseError] = []

    if not jsonl_path.exists():
        errors.append(JsonlParseError(str(jsonl_path), 0, "file_not_found", ""))
        return JsonlLoadResult(records=records, errors=errors)

    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw_line = line.rstrip("\n")
            if not raw_line.strip():
                continue
            try:
                data = json.loads(raw_line)
                if not isinstance(data, dict):
                    raise ValueError("JSONL record must be an object")
                records.append(factory(data))
            except Exception as exc:  # noqa: BLE001 - non-fatal record-level parse errors.
                LOGGER.warning("Failed to parse %s:%s: %s", jsonl_path, line_number, exc)
                errors.append(JsonlParseError(str(jsonl_path), line_number, str(exc), raw_line))
    return JsonlLoadResult(records=records, errors=errors)


def _records(value: Iterable[Any] | JsonlLoadResult) -> list[Any]:
    if isinstance(value, JsonlLoadResult):
        return list(value.records)
    return list(value)


def _function_key(sample_id: str, function_entry: str, function_name: str) -> tuple[str, str, str]:
    return (sample_id, function_entry, function_name)
