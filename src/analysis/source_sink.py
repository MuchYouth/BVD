"""Generic source and sink extraction helpers.

This module intentionally does not define CWE78 or CWE134 rules. Callers pass
in a normalized rule from `src.analysis.rule_registry`, and extraction logic
uses the rule's `sources` and `sinks` fields generically.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
import logging
from typing import Any

from src.analysis.rule_registry import CweRule
from src.pcode.schema import CallsiteRecord, FunctionPcode, JsonDict, PcodeOpRecord

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceCandidate:
    sample_id: str
    function_id: str
    source_type: str
    source_location: str
    source_varnodes: list[JsonDict]
    call_target_name: str = ""
    confidence: str = "medium"
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SinkCandidate:
    sample_id: str
    function_id: str
    sink_type: str
    sink_location: str
    sink_varnodes: list[JsonDict]
    call_target_name: str = ""
    argument_indices: list[int] = field(default_factory=list)
    confidence: str = "medium"
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SourceSinkPairCandidate:
    sample_id: str
    function_id: str
    source: SourceCandidate
    sink: SinkCandidate
    analysis_cwe: str
    warnings: list[str] = field(default_factory=list)


def extract_source_sink_pairs(
    functions: Iterable[FunctionPcode],
    rule: CweRule,
    *,
    unsupported_cwe_policy: str = "record_and_skip",
) -> list[SourceSinkPairCandidate]:
    """Build intraprocedural source-sink pair candidates using a loaded rule."""

    if rule.is_unsupported:
        if unsupported_cwe_policy == "record_and_skip":
            LOGGER.warning("Skipping unsupported CWE rule: %s", rule.cwe)
            return []
        raise ValueError(f"Unsupported CWE rule: {rule.cwe}")

    pairs: list[SourceSinkPairCandidate] = []
    for function in functions:
        sources = extract_source_candidates(function, rule)
        sinks = extract_sink_candidates(function, rule)
        for source in sources:
            for sink in sinks:
                warnings = []
                if rule.is_partially_supported:
                    warnings.append("experimental_rule_status:partially_supported")
                pairs.append(
                    SourceSinkPairCandidate(
                        sample_id=function.sample_id,
                        function_id=function.function_id,
                        source=source,
                        sink=sink,
                        analysis_cwe=rule.cwe,
                        warnings=warnings,
                    )
                )
    return pairs


def extract_source_candidates(function: FunctionPcode, rule: CweRule) -> list[SourceCandidate]:
    """Extract source candidates from callsites in one function."""

    if rule.is_unsupported:
        LOGGER.warning("Skipping source extraction for unsupported CWE rule: %s", rule.cwe)
        return []

    source_names = _lower_name_set(source_function_names(rule))
    op_by_address = _op_by_address(function.ops)
    candidates: list[SourceCandidate] = []

    for callsite in function.callsites:
        if _normalized_name(callsite.call_target_name) not in source_names:
            continue
        warnings = list(callsite.warnings)
        source_varnodes = _source_varnodes(callsite, op_by_address.get(callsite.call_address), warnings)
        if not source_varnodes:
            warnings.append("source_varnode_unknown")
        if source_parameter_names(rule):
            warnings.append("parameter_sources_not_implemented")
        if rule.is_partially_supported:
            warnings.append("experimental_rule_status:partially_supported")
        candidates.append(
            SourceCandidate(
                sample_id=function.sample_id,
                function_id=function.function_id,
                source_type="function_call",
                source_location=callsite.call_address,
                source_varnodes=source_varnodes,
                call_target_name=callsite.call_target_name,
                confidence="medium" if source_varnodes else "low",
                warnings=_dedupe(warnings),
            )
        )
    return candidates


def extract_sink_candidates(function: FunctionPcode, rule: CweRule) -> list[SinkCandidate]:
    """Extract sink candidates from callsites in one function."""

    if rule.is_unsupported:
        LOGGER.warning("Skipping sink extraction for unsupported CWE rule: %s", rule.cwe)
        return []

    sink_names = _lower_name_set(sink_function_names(rule))
    candidates: list[SinkCandidate] = []

    for callsite in function.callsites:
        target_key = _normalized_name(callsite.call_target_name)
        if target_key not in sink_names:
            continue
        warnings = list(callsite.warnings)
        argument_indices = sink_argument_indices(rule, callsite)
        sink_varnodes = _argument_varnodes(callsite, argument_indices, warnings)

        if rule.trace.get("type") == "taint_to_format_argument" and _all_constant_varnodes(sink_varnodes):
            continue
        if not sink_varnodes:
            warnings.append("sink_argument_varnode_unknown")
        if rule.is_partially_supported:
            warnings.append("experimental_rule_status:partially_supported")

        candidates.append(
            SinkCandidate(
                sample_id=function.sample_id,
                function_id=function.function_id,
                sink_type="function_call_argument",
                sink_location=callsite.call_address,
                sink_varnodes=sink_varnodes,
                call_target_name=callsite.call_target_name,
                argument_indices=argument_indices,
                confidence="medium" if sink_varnodes else "low",
                warnings=_dedupe(warnings),
            )
        )
    return candidates


def source_function_names(rule: CweRule) -> set[str]:
    """Return source function names defined by a rule."""

    return set(_string_items(rule.sources.get("functions", [])))


def source_parameter_names(rule: CweRule) -> set[str]:
    """Return source parameter names defined by a rule."""

    return set(_string_items(rule.sources.get("parameters", [])))


def sink_function_names(rule: CweRule) -> set[str]:
    """Return sink function names defined by a rule.

    Both regular call sinks and format-function maps are supported by the same
    generic accessor.
    """

    names = set(_string_items(rule.sinks.get("functions", [])))
    format_functions = rule.sinks.get("format_functions", {})
    if isinstance(format_functions, dict):
        names.update(str(name) for name in format_functions)
    return names


def sink_argument_index(rule: CweRule, function_name: str) -> int | None:
    """Return a sink argument index when the rule defines one."""

    format_functions = rule.sinks.get("format_functions", {})
    if not isinstance(format_functions, dict):
        return None
    value = format_functions.get(function_name)
    return int(value) if isinstance(value, int) else None


def sink_argument_indices(rule: CweRule, callsite: CallsiteRecord) -> list[int]:
    """Return sink-relevant argument indices for a callsite from rule metadata."""

    target_name = callsite.call_target_name
    target_key = _normalized_name(target_name)

    format_functions = rule.sinks.get("format_functions", {})
    if isinstance(format_functions, dict):
        for name, index in format_functions.items():
            if _normalized_name(str(name)) == target_key:
                return [int(index)]

    argument_indices = rule.sinks.get("argument_indices", {})
    if isinstance(argument_indices, dict):
        for name, indices in argument_indices.items():
            if _normalized_name(str(name)) == target_key:
                if isinstance(indices, list):
                    return [int(index) for index in indices]
                if isinstance(indices, int):
                    return [indices]

    argument_policy = rule.sinks.get("argument_policy", {})
    if isinstance(argument_policy, dict):
        for name, policy in argument_policy.items():
            if _normalized_name(str(name)) == target_key and str(policy).lower() == "all":
                return _all_argument_indices(callsite)

    return _all_argument_indices(callsite)


def _string_items(value: Any) -> Iterable[str]:
    if not isinstance(value, list):
        return []
    return (str(item) for item in value)


def _source_varnodes(
    callsite: CallsiteRecord,
    pcode_op: PcodeOpRecord | None,
    warnings: list[str],
) -> list[JsonDict]:
    varnodes: list[JsonDict] = []
    if pcode_op is not None and pcode_op.output_varnode is not None:
        varnodes.append(pcode_op.output_varnode)
    elif pcode_op is None:
        warnings.append("source_pcode_op_not_found")

    for argument in callsite.recovered_arguments:
        varnode = argument.get("varnode")
        if isinstance(varnode, dict):
            varnodes.append(varnode)
    if not varnodes:
        varnodes.extend(_raw_argument_varnodes(callsite))
    return _dedupe_varnodes(varnodes)


def _argument_varnodes(callsite: CallsiteRecord, argument_indices: list[int], warnings: list[str]) -> list[JsonDict]:
    varnodes: list[JsonDict] = []
    recovered_by_index = {
        int(argument["index"]): argument.get("varnode")
        for argument in callsite.recovered_arguments
        if isinstance(argument, dict) and "index" in argument
    }

    for index in argument_indices:
        recovered = recovered_by_index.get(index)
        if isinstance(recovered, dict):
            varnodes.append(recovered)
            continue

        raw_index = index + 1
        if 0 <= raw_index < len(callsite.raw_input_varnodes):
            varnodes.append(callsite.raw_input_varnodes[raw_index])
        else:
            warnings.append(f"argument_{index}_varnode_unavailable")
    return _dedupe_varnodes(varnodes)


def _raw_argument_varnodes(callsite: CallsiteRecord) -> list[JsonDict]:
    return list(callsite.raw_input_varnodes[1:])


def _all_argument_indices(callsite: CallsiteRecord) -> list[int]:
    recovered_indices = [
        int(argument["index"])
        for argument in callsite.recovered_arguments
        if isinstance(argument, dict) and "index" in argument
    ]
    if recovered_indices:
        return sorted(set(recovered_indices))
    return list(range(max(0, len(callsite.raw_input_varnodes) - 1)))


def _all_constant_varnodes(varnodes: list[JsonDict]) -> bool:
    return bool(varnodes) and all(_is_constant_varnode(varnode) for varnode in varnodes)


def _is_constant_varnode(varnode: JsonDict) -> bool:
    return bool(varnode.get("is_constant")) or str(varnode.get("space", "")).lower() == "constant"


def _op_by_address(ops: Iterable[PcodeOpRecord]) -> dict[str, PcodeOpRecord]:
    return {op.op_address: op for op in ops}


def _normalized_name(name: str) -> str:
    return name.lower()


def _lower_name_set(names: Iterable[str]) -> set[str]:
    return {_normalized_name(name) for name in names}


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _dedupe_varnodes(varnodes: Iterable[JsonDict]) -> list[JsonDict]:
    seen: set[tuple[tuple[str, Any], ...]] = set()
    deduped: list[JsonDict] = []
    for varnode in varnodes:
        key = tuple(sorted(varnode.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(varnode)
    return deduped
