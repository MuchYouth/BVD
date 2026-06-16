"""Leakage checks for model input and prompts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


DEFAULT_FORBIDDEN_PATTERNS = [
    "bad",
    "good",
    "CWE",
    "CWE78",
    "CWE134",
    "Juliet",
]


@dataclass(frozen=True)
class LeakageCheckResult:
    status: str
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": self.findings,
            "warnings": self.warnings,
        }


def check_model_input(
    model_input: dict[str, Any],
    *,
    source_filename: str = "",
    original_function_name: str = "",
    extra_forbidden: list[str] | None = None,
) -> LeakageCheckResult:
    text = json.dumps(model_input, sort_keys=True)
    forbidden = list(DEFAULT_FORBIDDEN_PATTERNS)
    if source_filename:
        forbidden.append(source_filename)
    if original_function_name:
        forbidden.append(original_function_name)
    if extra_forbidden:
        forbidden.extend(extra_forbidden)

    findings: list[str] = []
    for pattern in forbidden:
        if not pattern:
            continue
        if re.search(re.escape(pattern), text, flags=re.IGNORECASE):
            findings.append(pattern)

    findings = list(dict.fromkeys(findings))
    warnings = [f"leakage_pattern_found:{finding}" for finding in findings]
    return LeakageCheckResult(status="failed" if findings else "passed", findings=findings, warnings=warnings)
