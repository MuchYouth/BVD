"""Attach Ghidra evidence to LLMDFA records without dataflow analysis."""

from __future__ import annotations

from typing import Any

from src.ghidra_evidence.schema import FunctionEvidence, SampleEvidence


def attach_ghidra_evidence(
    llmdfa_record: dict[str, Any],
    sample_evidence: SampleEvidence | None,
    *,
    function_entry: str = "",
    function_id: str = "",
) -> dict[str, Any]:
    warnings = list(llmdfa_record.get("warnings", []))
    evidence = select_function_evidence(sample_evidence, function_entry=function_entry, function_id=function_id)
    if sample_evidence is None:
        warnings.append("ghidra_evidence_missing")
        evidence_payload: dict[str, Any] = {}
    elif evidence is None:
        warnings.append("function_evidence_not_matched")
        evidence_payload = {
            "sample_id": sample_evidence.sample_id,
            "pcode_path": sample_evidence.pcode_path,
            "callsites_path": sample_evidence.callsites_path,
            "functions_available": len(sample_evidence.functions),
            "parser_errors": sample_evidence.parser_errors,
            "warnings": sample_evidence.warnings,
        }
    else:
        evidence_payload = evidence.to_dict()
        evidence_payload["pcode_path"] = sample_evidence.pcode_path
        evidence_payload["callsites_path"] = sample_evidence.callsites_path
        evidence_payload["sample_warnings"] = sample_evidence.warnings
        evidence_payload["sample_parser_errors"] = sample_evidence.parser_errors

    return {
        **llmdfa_record,
        "ghidra_evidence": evidence_payload,
        "warnings": list(dict.fromkeys(warnings)),
    }


def select_function_evidence(
    sample_evidence: SampleEvidence | None,
    *,
    function_entry: str = "",
    function_id: str = "",
) -> FunctionEvidence | None:
    if sample_evidence is None:
        return None
    if function_entry:
        for function in sample_evidence.functions:
            if function.function_entry == function_entry:
                return function
    if function_id:
        for function in sample_evidence.functions:
            if function.function_id == function_id:
                return function
    if len(sample_evidence.functions) == 1:
        return sample_evidence.functions[0]
    return None

