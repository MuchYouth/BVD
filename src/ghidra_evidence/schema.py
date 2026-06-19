"""Schemas for binary-level evidence attached to LLMDFA results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FunctionEvidence:
    sample_id: str
    function_id: str
    original_function_name: str
    function_entry: str
    pcode_ops: list[dict[str, Any]] = field(default_factory=list)
    callsites: list[dict[str, Any]] = field(default_factory=list)
    parser_errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "function_id": self.function_id,
            "original_function_name": self.original_function_name,
            "function_entry": self.function_entry,
            "pcode_ops": self.pcode_ops,
            "callsites": self.callsites,
            "parser_errors": self.parser_errors,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class SampleEvidence:
    sample_id: str
    pcode_path: str
    callsites_path: str
    functions: list[FunctionEvidence] = field(default_factory=list)
    parser_errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "pcode_path": self.pcode_path,
            "callsites_path": self.callsites_path,
            "functions": [function.to_dict() for function in self.functions],
            "parser_errors": self.parser_errors,
            "warnings": self.warnings,
        }

