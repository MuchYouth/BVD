"""LLM trace review adapter.

The LLM is a reviewer/summarizer only. Its output must never overwrite labels
or Juliet-derived metadata.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.analysis.prompts import PROMPT_VERSION, build_pcode_dataflow_prompt


@dataclass(frozen=True)
class LLMReviewResult:
    enabled: bool
    provider: str
    model: str
    prompt_version: str
    answer: str
    reason: str
    relevant_ops: list[int] = field(default_factory=list)
    confidence: float = 0.0
    raw_response: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "answer": self.answer,
            "reason": self.reason,
            "relevant_ops": self.relevant_ops,
            "confidence": self.confidence,
            "raw_response": self.raw_response,
            "error": self.error,
        }


class LLMClient(Protocol):
    provider: str
    model: str
    temperature: float

    def review_trace(
        self,
        *,
        function_ops: list[dict[str, Any]],
        source: dict[str, Any],
        sink: dict[str, Any],
        trace_candidate: dict[str, Any],
    ) -> LLMReviewResult:
        ...


class MockLLMClient:
    provider = "mock"

    def __init__(self, model: str = "mock", temperature: float = 0.0, enabled: bool = False) -> None:
        self.model = model
        self.temperature = temperature
        self.enabled = enabled

    def review_trace(
        self,
        *,
        function_ops: list[dict[str, Any]],
        source: dict[str, Any],
        sink: dict[str, Any],
        trace_candidate: dict[str, Any],
    ) -> LLMReviewResult:
        return LLMReviewResult(
            enabled=self.enabled,
            provider=self.provider,
            model=self.model,
            prompt_version=PROMPT_VERSION,
            answer="unknown",
            reason="mock_result_llm_disabled" if not self.enabled else "mock_result_no_external_call",
            relevant_ops=[],
            confidence=0.0,
            raw_response="",
            error="",
        )


class OpenAIClient:
    provider = "openai"

    def __init__(self, model: str, temperature: float = 0.0, api_key_env: str = "OPENAI_API_KEY") -> None:
        self.model = model
        self.temperature = temperature
        self.api_key_env = api_key_env
        self.api_key = os.environ.get(api_key_env, "")

    def review_trace(
        self,
        *,
        function_ops: list[dict[str, Any]],
        source: dict[str, Any],
        sink: dict[str, Any],
        trace_candidate: dict[str, Any],
    ) -> LLMReviewResult:
        prompt = build_pcode_dataflow_prompt(function_ops, source, sink, trace_candidate)
        if not self.api_key:
            return LLMReviewResult(
                enabled=True,
                provider=self.provider,
                model=self.model,
                prompt_version=PROMPT_VERSION,
                answer="unknown",
                reason="openai_api_key_missing",
                confidence=0.0,
                raw_response="",
                error=f"{self.api_key_env} is not set",
            )

        return LLMReviewResult(
            enabled=True,
            provider=self.provider,
            model=self.model,
            prompt_version=PROMPT_VERSION,
            answer="unknown",
            reason="openai_client_skeleton_not_implemented",
            confidence=0.0,
            raw_response=prompt,
            error="OpenAI API call is intentionally not implemented in this MVP adapter",
        )


def client_from_config(config: dict[str, Any]) -> LLMClient:
    llm_config = config.get("llm", {})
    enabled = bool(llm_config.get("enabled", False))
    provider = str(llm_config.get("provider", "mock")).lower()
    model = str(llm_config.get("model", "mock"))
    temperature = float(llm_config.get("temperature", 0))

    if not enabled:
        return MockLLMClient(model=model, temperature=temperature, enabled=False)
    if provider == "openai":
        return OpenAIClient(model=model, temperature=temperature)
    return MockLLMClient(model=model, temperature=temperature, enabled=True)


def parse_llm_json_response(raw_response: str) -> tuple[dict[str, Any] | None, str]:
    try:
        data = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "LLM response JSON must be an object"
    return data, ""


def review_trace_with_client(
    client: LLMClient,
    *,
    function_ops: list[dict[str, Any]],
    source: dict[str, Any],
    sink: dict[str, Any],
    trace_candidate: dict[str, Any],
) -> LLMReviewResult:
    result = client.review_trace(
        function_ops=function_ops,
        source=source,
        sink=sink,
        trace_candidate=trace_candidate,
    )
    if not result.raw_response:
        return result

    parsed, error = parse_llm_json_response(result.raw_response)
    if error:
        return LLMReviewResult(
            enabled=result.enabled,
            provider=result.provider,
            model=result.model,
            prompt_version=result.prompt_version,
            answer=result.answer,
            reason=result.reason,
            confidence=result.confidence,
            raw_response=result.raw_response,
            error=error,
        )
    return LLMReviewResult(
        enabled=result.enabled,
        provider=result.provider,
        model=result.model,
        prompt_version=result.prompt_version,
        answer=str(parsed.get("answer", "unknown")),
        reason=str(parsed.get("reason", "")),
        relevant_ops=[int(op) for op in parsed.get("relevant_ops", []) if isinstance(op, int)],
        confidence=float(parsed.get("confidence", 0.0)),
        raw_response=result.raw_response,
        error="",
    )
