"""DeepSeek adapter for Hexbreaker.

DeepSeek's API is OpenAI-compatible, so we POST to /v1/chat/completions with
httpx. Two roles in play:

- V4-flash (`deepseek-chat`): Prosecutor, Witness, Provocateur, Forge generator.
  Fast, cheap, ~$0.0003/call.
- V4-pro reasoner (`deepseek-reasoner`): Defender only. The `reasoning_content`
  field is the visible chain-of-thought we need for the demo's self-correction
  moment, per plan.

The Judge is deterministic Python — it never calls this module.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Literal

import httpx
import orjson
from pydantic import BaseModel
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
DEEPSEEK_CHAT = "deepseek-chat"
DEEPSEEK_REASONER = "deepseek-reasoner"

Role = Literal["system", "user", "assistant"]


class Message(BaseModel):
    role: Role
    content: str


class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class LLMResponse(BaseModel):
    model: str
    content: str
    reasoning_content: str | None = None
    usage: Usage
    latency_s: float
    raw: dict[str, Any]


class LLMError(RuntimeError):
    """Raised when the provider returns a non-retryable error."""


def load_env(path: str | Path = ".env") -> None:
    """Minimal .env loader — only sets keys that aren't already in os.environ."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v and k not in os.environ:
            os.environ[k] = v


class DeepSeekClient:
    """Thin httpx client for DeepSeek chat completions.

    Retries on transient network/5xx errors. 4xx errors raise LLMError without
    retry — auth/quota problems shouldn't burn our retry budget.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEEPSEEK_BASE_URL,
        timeout: float = 60.0,
    ) -> None:
        key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        if not key:
            raise LLMError("DEEPSEEK_API_KEY not set — call load_env() or set the env var")
        self._key = key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def call(
        self,
        messages: list[Message] | list[dict[str, str]],
        *,
        model: str = DEEPSEEK_CHAT,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        msgs = [m.model_dump() if isinstance(m, Message) else m for m in messages]
        payload: dict[str, Any] = {
            "model": model,
            "messages": msgs,
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        t0 = time.monotonic()
        data = self._post(payload)
        latency = time.monotonic() - t0

        choice = data["choices"][0]["message"]
        return LLMResponse(
            model=data.get("model", model),
            content=choice.get("content") or "",
            reasoning_content=choice.get("reasoning_content"),
            usage=Usage(**data["usage"]),
            latency_s=latency,
            raw=data,
        )

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=1, min=1, max=20),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(url, headers=headers, content=orjson.dumps(payload))
        if 400 <= resp.status_code < 500:
            # Auth/quota/bad-request — not retryable. Surface as LLMError directly.
            raise LLMError(f"DeepSeek {resp.status_code}: {resp.text[:500]}")
        resp.raise_for_status()
        return resp.json()
