"""DEPRECATED: P-code def-use based trace candidate builder.

This module is preserved only for future optional experiments. The primary
pipeline must not use custom P-code def-use or backward-slicing trace decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from src.analysis.source_sink import SinkCandidate, SourceCandidate, SourceSinkPairCandidate
from src.pcode.schema import JsonDict, PcodeOpRecord

PathStatus = Literal[True, False, "unknown"]


@dataclass(frozen=True)
class DefUseIndex:
    defining_ops: dict[tuple[tuple[str, Any], ...], PcodeOpRecord]
    using_ops: dict[tuple[tuple[str, Any], ...], list[PcodeOpRecord]]


@dataclass(frozen=True)
class TraceCandidate:
    sample_id: str
    function_id: str
    source: SourceCandidate
    sink: SinkCandidate
    path_found: PathStatus
    trace_ops: list[dict[str, Any]]
    reason: str
    analysis_mode: str = "rule_based_intraprocedural"
    warnings: list[str] = field(default_factory=list)
    analysis_cwe: str = ""
    trace_type: str = ""


def build_def_use_index(ops: list[PcodeOpRecord]) -> DefUseIndex:
    """Build simple varnode -> defining op and varnode -> using ops indexes."""

    defining_ops: dict[tuple[tuple[str, Any], ...], PcodeOpRecord] = {}
    using_ops: dict[tuple[tuple[str, Any], ...], list[PcodeOpRecord]] = {}

    for op in ops:
        output_key = varnode_key(op.output_varnode)
        if output_key is not None:
            defining_ops[output_key] = op
        for input_varnode in op.input_varnodes:
            input_key = varnode_key(input_varnode)
            if input_key is None:
                continue
            using_ops.setdefault(input_key, []).append(op)
    return DefUseIndex(defining_ops=defining_ops, using_ops=using_ops)


def backward_slice_to_source(
    ops: list[PcodeOpRecord],
    source: SourceCandidate,
    sink: SinkCandidate,
    *,
    max_depth: int = 64,
) -> TraceCandidate:
    """Backward slice from sink argument varnodes toward source varnodes/op."""

    warnings = _dedupe([*source.warnings, *sink.warnings])
    if not sink.sink_varnodes:
        return TraceCandidate(
            sample_id=sink.sample_id,
            function_id=sink.function_id,
            source=source,
            sink=sink,
            path_found="unknown",
            trace_ops=[],
            reason="sink_varnode_unknown",
            warnings=warnings,
        )
    if not source.source_varnodes and not source.source_location:
        return TraceCandidate(
            sample_id=sink.sample_id,
            function_id=sink.function_id,
            source=source,
            sink=sink,
            path_found="unknown",
            trace_ops=[],
            reason="source_varnode_unknown",
            warnings=warnings,
        )

    index = build_def_use_index(ops)
    op_by_address = {op.op_address: op for op in ops}
    source_keys = {key for key in (varnode_key(varnode) for varnode in source.source_varnodes) if key is not None}
    source_op = op_by_address.get(source.source_location)
    source_op_address = source_op.op_address if source_op is not None else source.source_location

    visited_varnodes: set[tuple[tuple[str, Any], ...]] = set()
    visited_ops: set[str] = set()
    trace_ops: list[PcodeOpRecord] = []
    stack: list[tuple[tuple[tuple[str, Any], ...], int]] = []

    for sink_varnode in sink.sink_varnodes:
        key = varnode_key(sink_varnode)
        if key is None:
            warnings.append("sink_varnode_unkeyable")
            continue
        stack.append((key, 0))

    if not stack:
        return TraceCandidate(
            sample_id=sink.sample_id,
            function_id=sink.function_id,
            source=source,
            sink=sink,
            path_found="unknown",
            trace_ops=[],
            reason="sink_varnode_unknown",
            warnings=_dedupe(warnings),
        )

    while stack:
        current_key, depth = stack.pop()
        if current_key in source_keys:
            return _trace_result(source, sink, True, trace_ops, "source_varnode_reached", warnings)
        if depth > max_depth:
            warnings.append("max_depth_reached")
            continue
        if current_key in visited_varnodes:
            continue
        visited_varnodes.add(current_key)

        defining_op = index.defining_ops.get(current_key)
        if defining_op is None:
            continue
        if defining_op.op_address not in visited_ops:
            trace_ops.append(defining_op)
            visited_ops.add(defining_op.op_address)

        if defining_op.op_address == source_op_address:
            return _trace_result(source, sink, True, trace_ops, "source_op_reached", warnings)

        if _memory_model_unknown(defining_op):
            return _trace_result(source, sink, "unknown", trace_ops, "memory_model_unknown", [*warnings, "memory_model_simplified"])

        for input_varnode in defining_op.input_varnodes:
            input_key = varnode_key(input_varnode)
            if input_key is not None:
                stack.append((input_key, depth + 1))

    return _trace_result(source, sink, False, trace_ops, "no_path", warnings)


def build_trace_candidates(
    ops: list[PcodeOpRecord],
    pairs: list[SourceSinkPairCandidate],
    *,
    trace_type: str = "",
    max_depth: int = 64,
) -> list[TraceCandidate]:
    """Build trace candidates for source-sink pairs in one function."""

    traces: list[TraceCandidate] = []
    for pair in pairs:
        trace = backward_slice_to_source(ops, pair.source, pair.sink, max_depth=max_depth)
        traces.append(
            TraceCandidate(
                sample_id=trace.sample_id,
                function_id=trace.function_id,
                source=trace.source,
                sink=trace.sink,
                path_found=trace.path_found,
                trace_ops=trace.trace_ops,
                reason=trace.reason,
                analysis_mode=trace.analysis_mode,
                warnings=_dedupe([*pair.warnings, *trace.warnings]),
                analysis_cwe=pair.analysis_cwe,
                trace_type=trace_type,
            )
        )
    return traces


def varnode_key(varnode: JsonDict | None) -> tuple[tuple[str, Any], ...] | None:
    """Return a hashable identity for a varnode."""

    if not isinstance(varnode, dict):
        return None
    return tuple(
        sorted(
            {
                "space": str(varnode.get("space", "")),
                "address": str(varnode.get("address", "")),
                "offset": int(varnode.get("offset", 0)),
                "size": int(varnode.get("size", 0)),
                "is_constant": bool(varnode.get("is_constant", False)),
            }.items()
        )
    )


def _trace_result(
    source: SourceCandidate,
    sink: SinkCandidate,
    path_found: PathStatus,
    trace_ops: list[PcodeOpRecord],
    reason: str,
    warnings: list[str],
) -> TraceCandidate:
    return TraceCandidate(
        sample_id=sink.sample_id,
        function_id=sink.function_id,
        source=source,
        sink=sink,
        path_found=path_found,
        trace_ops=[trace_op_summary(op) for op in sorted(trace_ops, key=lambda record: record.op_seq)],
        reason=reason,
        warnings=_dedupe(warnings),
    )


def trace_op_summary(op: PcodeOpRecord) -> dict[str, Any]:
    return {
        "op_seq": op.op_seq,
        "op_address": op.op_address,
        "mnemonic": op.mnemonic,
        "opcode": op.opcode,
        "output_varnode": op.output_varnode,
        "input_varnodes": op.input_varnodes,
    }


def _memory_model_unknown(op: PcodeOpRecord) -> bool:
    mnemonic = op.mnemonic.upper()
    return mnemonic in {"LOAD", "STORE", "PTRADD", "PTRSUB", "INDIRECT"}


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
