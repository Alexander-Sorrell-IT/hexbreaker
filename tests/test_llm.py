"""Unit tests for the DeepSeek adapter.

The unit tests mock _post entirely so no real API calls are made. An integration
test is provided but skipped unless HEXBREAKER_RUN_LIVE=1 and DEEPSEEK_API_KEY
are set in the environment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from hexbreaker import llm


@pytest.fixture
def fake_chat_response() -> dict[str, Any]:
    return {
        "id": "chatcmpl-fake",
        "model": "deepseek-chat",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
    }


@pytest.fixture
def fake_reasoner_response() -> dict[str, Any]:
    return {
        "id": "chatcmpl-fake-r",
        "model": "deepseek-reasoner",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '{"verdict": "CONTESTED"}',
                    "reasoning_content": "Step 1: examine cited evidence ... ",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    }


def test_call_parses_chat_response(monkeypatch: pytest.MonkeyPatch, fake_chat_response: dict[str, Any]) -> None:
    captured: dict[str, Any] = {}

    def fake_post(self, payload):
        captured["payload"] = payload
        return fake_chat_response

    monkeypatch.setattr(llm.DeepSeekClient, "_post", fake_post)
    c = llm.DeepSeekClient(api_key="test-key")
    resp = c.call([{"role": "user", "content": "hi"}])
    assert resp.content == "hello"
    assert resp.reasoning_content is None
    assert resp.usage.total_tokens == 6
    assert resp.model == "deepseek-chat"
    assert resp.latency_s >= 0


def test_call_captures_reasoning_content(monkeypatch: pytest.MonkeyPatch, fake_reasoner_response: dict[str, Any]) -> None:
    monkeypatch.setattr(llm.DeepSeekClient, "_post", lambda self, p: fake_reasoner_response)
    c = llm.DeepSeekClient(api_key="test-key")
    resp = c.call(
        [{"role": "user", "content": "review claim"}],
        model=llm.DEEPSEEK_REASONER,
    )
    assert resp.content == '{"verdict": "CONTESTED"}'
    assert resp.reasoning_content is not None
    assert "Step 1" in resp.reasoning_content


def test_json_mode_sets_response_format(monkeypatch: pytest.MonkeyPatch, fake_chat_response: dict[str, Any]) -> None:
    captured: dict[str, Any] = {}

    def fake_post(self, payload):
        captured["payload"] = payload
        return fake_chat_response

    monkeypatch.setattr(llm.DeepSeekClient, "_post", fake_post)
    c = llm.DeepSeekClient(api_key="test-key")
    c.call([{"role": "user", "content": "respond in json"}], json_mode=True)
    assert captured["payload"]["response_format"] == {"type": "json_object"}


def test_missing_api_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(llm.LLMError, match="DEEPSEEK_API_KEY"):
        llm.DeepSeekClient()


def test_message_model_serializes_cleanly() -> None:
    m = llm.Message(role="user", content="hi")
    assert m.model_dump() == {"role": "user", "content": "hi"}


def test_load_env_reads_file_without_overriding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("FOO=from_file\nBAR=other\n")
    monkeypatch.delenv("FOO", raising=False)
    monkeypatch.setenv("BAR", "preset")
    llm.load_env(env_path)
    assert os.environ["FOO"] == "from_file"
    assert os.environ["BAR"] == "preset"  # not overridden


@pytest.mark.skipif(
    os.environ.get("HEXBREAKER_RUN_LIVE") != "1",
    reason="live API test — set HEXBREAKER_RUN_LIVE=1 + DEEPSEEK_API_KEY to run",
)
def test_live_chat_smoke() -> None:
    llm.load_env()
    c = llm.DeepSeekClient()
    resp = c.call(
        [{"role": "user", "content": "Reply with exactly the word: pong"}],
        temperature=0.0,
        max_tokens=8,
    )
    assert "pong" in resp.content.lower()
    assert resp.usage.total_tokens > 0
