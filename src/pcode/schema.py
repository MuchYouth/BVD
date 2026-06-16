"""Schemas for raw and normalized P-code records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


JsonDict = dict[str, Any]


@dataclass(frozen=True)
class JsonlParseError:
    """A JSONL parsing error with file and line provenance."""

    path: str
    line_number: int
    message: str
    raw_line: str


@dataclass(frozen=True)
class JsonlLoadResult:
    """Parsed JSONL records plus non-fatal line errors."""

    records: list[Any]
    errors: list[JsonlParseError] = field(default_factory=list)

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> Any:
        return self.records[index]


@dataclass(frozen=True)
class PcodeOpRecord:
    sample_id: str
    function_name: str
    function_entry: str
    op_seq: int
    op_address: str
    mnemonic: str
    opcode: int
    output_varnode: JsonDict | None
    input_varnodes: list[JsonDict]
    warnings: list[str] = field(default_factory=list)
    binary_name: str = ""
    basic_block: str = ""

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PcodeOpRecord":
        return cls(
            sample_id=str(data.get("sample_id", "")),
            function_name=str(data.get("function_name", "")),
            function_entry=str(data.get("function_entry", "")),
            op_seq=int(data.get("op_seq", 0)),
            op_address=str(data.get("op_address", "")),
            mnemonic=str(data.get("mnemonic", "")),
            opcode=int(data.get("opcode", 0)),
            output_varnode=_optional_dict(data.get("output_varnode")),
            input_varnodes=_list_of_dicts(data.get("input_varnodes")),
            warnings=_list_of_strings(data.get("warnings")),
            binary_name=str(data.get("binary_name", "")),
            basic_block=str(data.get("basic_block", "")),
        )

    def to_dict(self) -> JsonDict:
        return {
            "sample_id": self.sample_id,
            "function_name": self.function_name,
            "function_entry": self.function_entry,
            "op_seq": self.op_seq,
            "op_address": self.op_address,
            "mnemonic": self.mnemonic,
            "opcode": self.opcode,
            "output_varnode": self.output_varnode,
            "input_varnodes": self.input_varnodes,
            "warnings": self.warnings,
            "binary_name": self.binary_name,
            "basic_block": self.basic_block,
        }


@dataclass(frozen=True)
class CallsiteRecord:
    sample_id: str
    function_name: str
    function_entry: str
    call_address: str
    call_target_address: str
    call_target_name: str
    is_external: bool
    raw_input_varnodes: list[JsonDict]
    recovered_arguments: list[JsonDict]
    argument_recovery_confidence: str
    warnings: list[str] = field(default_factory=list)
    binary_name: str = ""

    @classmethod
    def from_dict(cls, data: JsonDict) -> "CallsiteRecord":
        return cls(
            sample_id=str(data.get("sample_id", "")),
            function_name=str(data.get("function_name", "")),
            function_entry=str(data.get("function_entry", "")),
            call_address=str(data.get("call_address", "")),
            call_target_address=str(data.get("call_target_address", "")),
            call_target_name=str(data.get("call_target_name", "")),
            is_external=bool(data.get("is_external", False)),
            raw_input_varnodes=_list_of_dicts(data.get("raw_input_varnodes")),
            recovered_arguments=_list_of_dicts(data.get("recovered_arguments")),
            argument_recovery_confidence=str(data.get("argument_recovery_confidence", "unknown")),
            warnings=_list_of_strings(data.get("warnings")),
            binary_name=str(data.get("binary_name", "")),
        )

    def to_dict(self) -> JsonDict:
        return {
            "sample_id": self.sample_id,
            "function_name": self.function_name,
            "function_entry": self.function_entry,
            "call_address": self.call_address,
            "call_target_address": self.call_target_address,
            "call_target_name": self.call_target_name,
            "is_external": self.is_external,
            "raw_input_varnodes": self.raw_input_varnodes,
            "recovered_arguments": self.recovered_arguments,
            "argument_recovery_confidence": self.argument_recovery_confidence,
            "warnings": self.warnings,
            "binary_name": self.binary_name,
        }


@dataclass(frozen=True)
class FunctionPcode:
    sample_id: str
    function_id: str
    original_function_name: str
    function_entry: str
    ops: list[PcodeOpRecord] = field(default_factory=list)
    callsites: list[CallsiteRecord] = field(default_factory=list)


def _optional_dict(value: Any) -> JsonDict | None:
    return dict(value) if isinstance(value, dict) else None


def _list_of_dicts(value: Any) -> list[JsonDict]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
