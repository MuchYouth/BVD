"""Provider-neutral chat client for FreeLLMAPI and OpenAI."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


class LLMClientError(RuntimeError):
    """Raised when a provider request cannot produce a usable response."""


@dataclass(frozen=True)
class ChatResult:
    text: str
    provider: str
    model: str
    endpoint: str
    usage: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)


class ChatClient(Protocol):
    provider: str
    model: str

    def health_check(self) -> dict[str, Any]:
        ...

    def complete(self, *, system_prompt: str, user_prompt: str) -> ChatResult:
        ...


class OpenAICompatibleClient:
    """Call an OpenAI-compatible chat-completions endpoint using stdlib HTTP."""

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        base_url: str,
        api_key: str = "",
        temperature: float = 0.0,
        timeout_sec: int = 120,
        completion_paths: tuple[str, ...] | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.timeout_sec = timeout_sec
        self.completion_paths = completion_paths or ("/v1/chat/completions",)

    def health_check(self) -> dict[str, Any]:
        if self.provider == "openai":
            return {"status": "configured", "provider": self.provider, "base_url": self.base_url}
        url = f"{self.base_url}/api/ping"
        try:
            payload = self._request(url, method="GET")
        except LLMClientError as exc:
            return {"status": "unavailable", "provider": self.provider, "url": url, "error": str(exc)}
        return {"status": "ok", "provider": self.provider, "url": url, "response": payload}

    def complete(self, *, system_prompt: str, user_prompt: str) -> ChatResult:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
        }
        errors: list[str] = []
        for path in self.completion_paths:
            endpoint = f"{self.base_url}{path}"
            try:
                payload = self._request(endpoint, body=body)
            except LLMClientError as exc:
                errors.append(f"{endpoint}: {exc}")
                continue
            text = extract_response_text(payload)
            if text:
                return ChatResult(
                    text=text,
                    provider=self.provider,
                    model=self.model,
                    endpoint=endpoint,
                    usage=dict(payload.get("usage", {})) if isinstance(payload, dict) else {},
                    raw_response=payload if isinstance(payload, dict) else {"response": payload},
                )
            errors.append(f"{endpoint}: response did not contain assistant text")
        raise LLMClientError("; ".join(errors))

    def _request(
        self,
        url: str,
        *,
        method: str = "POST",
        body: dict[str, Any] | None = None,
    ) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_sec) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise LLMClientError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMClientError(str(exc)) from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"text": raw}


def client_from_settings(
    *,
    provider: str,
    model: str,
    base_url: str | None = None,
    api_key_env: str | None = None,
    temperature: float = 0.0,
    timeout_sec: int = 120,
) -> OpenAICompatibleClient:
    normalized = provider.lower()
    if normalized == "freellm":
        env_name = api_key_env or "FREELLM_API_KEY"
        return OpenAICompatibleClient(
            provider=normalized,
            model=model,
            base_url=base_url or "http://127.0.0.1:3001",
            api_key=os.environ.get(env_name, ""),
            temperature=temperature,
            timeout_sec=timeout_sec,
        )
    if normalized == "openai":
        env_name = api_key_env or "OPENAI_API_KEY"
        api_key = os.environ.get(env_name, "")
        if not api_key:
            raise LLMClientError(f"{env_name} is not set")
        return OpenAICompatibleClient(
            provider=normalized,
            model=model,
            base_url=base_url or "https://api.openai.com",
            api_key=api_key,
            temperature=temperature,
            timeout_sec=timeout_sec,
            completion_paths=("/v1/chat/completions",),
        )
    raise LLMClientError(f"Unsupported provider: {provider}")


def extract_response_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return str(payload or "")
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        choice = choices[0]
        if isinstance(choice, dict):
            message = choice.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"].strip()
            if isinstance(choice.get("text"), str):
                return choice["text"].strip()
    for key in ("response", "content", "text", "message"):
        value = payload.get(key)
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, dict) and isinstance(value.get("content"), str):
            return value["content"].strip()
    return ""
