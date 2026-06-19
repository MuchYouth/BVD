"""DEPRECATED: P-code normalization helpers for optional experiments.

The primary pipeline reads P-code/callsite JSONL as binary evidence and does
not use normalized P-code for model input, source/sink extraction, dataflow, or
trace generation.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from src.pcode.parser import group_records_by_function as parser_group_records_by_function
from src.pcode.schema import CallsiteRecord, FunctionPcode, PcodeOpRecord


def normalize_varnode(varnode: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a stable varnode representation with string-safe fields."""

    if varnode is None:
        return None
    return {
        "space": str(varnode.get("space", "")),
        "address": str(varnode.get("address", "")),
        "offset": int(varnode.get("offset", 0)),
        "size": int(varnode.get("size", 0)),
        "is_constant": bool(varnode.get("is_constant", False)),
        "is_unique": bool(varnode.get("is_unique", False)),
        "is_register": bool(varnode.get("is_register", False)),
        "is_address": bool(varnode.get("is_address", False)),
        "is_addr_tied": bool(varnode.get("is_addr_tied", False)),
    }


def anonymize_function_name(index: int) -> str:
    """Return a stable anonymous function id such as func_0001."""

    return f"func_{index:04d}"


def build_function_id_map(functions: Iterable[FunctionPcode]) -> dict[tuple[str, str, str], str]:
    """Build deterministic function-id mapping from grouped functions."""

    keys = sorted(
        {
            (function.sample_id, function.function_entry, function.original_function_name)
            for function in functions
        }
    )
    return {key: anonymize_function_name(index) for index, key in enumerate(keys, start=1)}


def group_by_function(
    pcode_records: Iterable[PcodeOpRecord],
    callsite_records: Iterable[CallsiteRecord],
    *,
    anonymize_symbols: bool = True,
) -> list[FunctionPcode]:
    """Group records and optionally anonymize function names for model input."""

    functions = parser_group_records_by_function(pcode_records, callsite_records)
    if not anonymize_symbols:
        return [
            replace(
                function,
                function_id=function.original_function_name or function.function_id,
                ops=[normalize_pcode_op(op) for op in function.ops],
                callsites=[normalize_callsite(callsite) for callsite in function.callsites],
            )
            for function in functions
        ]
    return anonymize_symbols_in_functions(functions)


def anonymize_symbols(functions: Iterable[FunctionPcode]) -> list[FunctionPcode]:
    """Public alias for anonymizing grouped function records."""

    return anonymize_symbols_in_functions(functions)


def anonymize_symbols_in_functions(functions: Iterable[FunctionPcode]) -> list[FunctionPcode]:
    function_list = list(functions)
    id_map = build_function_id_map(function_list)
    anonymized: list[FunctionPcode] = []

    for function in function_list:
        key = (function.sample_id, function.function_entry, function.original_function_name)
        function_id = id_map[key]
        anonymized.append(
            FunctionPcode(
                sample_id=function.sample_id,
                function_id=function_id,
                original_function_name=function.original_function_name,
                function_entry=function.function_entry,
                ops=[normalize_pcode_op(op, function_name=function_id) for op in function.ops],
                callsites=[normalize_callsite(callsite, function_name=function_id) for callsite in function.callsites],
            )
        )
    return anonymized


def normalize_pcode_op(record: PcodeOpRecord, *, function_name: str | None = None) -> PcodeOpRecord:
    return replace(
        record,
        function_name=function_name if function_name is not None else record.function_name,
        output_varnode=normalize_varnode(record.output_varnode),
        input_varnodes=[vn for vn in (normalize_varnode(varnode) for varnode in record.input_varnodes) if vn is not None],
    )


def normalize_callsite(record: CallsiteRecord, *, function_name: str | None = None) -> CallsiteRecord:
    return replace(
        record,
        function_name=function_name if function_name is not None else record.function_name,
        raw_input_varnodes=[vn for vn in (normalize_varnode(varnode) for varnode in record.raw_input_varnodes) if vn is not None],
        recovered_arguments=[normalize_argument(argument) for argument in record.recovered_arguments],
    )


def normalize_argument(argument: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(argument)
    if isinstance(normalized.get("varnode"), dict):
        normalized["varnode"] = normalize_varnode(normalized["varnode"])
    return normalized
