"""Dataset record schemas."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from src.dataset.leakage_check import LeakageCheckResult


@dataclass(frozen=True)
class DatasetRecord:
    record_id: str
    sample_id: str
    cwe: str
    variant: str
    binary_info: dict[str, Any]
    function_id: str
    llmdfa_result: dict[str, Any]
    ghidra_evidence: dict[str, Any]
    analysis_mode: str
    metadata: dict[str, Any]
    model_input: dict[str, Any]
    leakage_check: LeakageCheckResult
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["leakage_check"] = self.leakage_check.to_dict()
        return data
