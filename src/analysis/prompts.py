"""Prompt builders for LLM trace review."""

from __future__ import annotations

import json
from typing import Any

PROMPT_VERSION = "pcode_dataflow_review_v1"


def build_pcode_dataflow_prompt(
    function_ops: list[dict[str, Any]],
    source: dict[str, Any],
    sink: dict[str, Any],
    trace_candidate: dict[str, Any],
    max_ops: int = 80,
) -> str:
    """Build a label-free prompt for reviewing one trace candidate."""

    payload = {
        "prompt_version": PROMPT_VERSION,
        "function_ops": function_ops[:max_ops],
        "source_candidate": source,
        "sink_candidate": sink,
        "trace_candidate": trace_candidate,
        "question": "Does the value from the source operation flow to the sink argument operation?",
        "required_output_json": {
            "answer": "yes|no|unknown",
            "reason": "...",
            "relevant_ops": ["op_seq..."],
            "confidence": 0.0,
        },
    }
    return (
        "You are reviewing an anonymized P-code dataflow trace candidate. "
        "Do not infer labels or vulnerability ground truth. Respond only as JSON.\n"
        + json.dumps(payload, sort_keys=True)
    )
