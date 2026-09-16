"""Prahari AI chat: prompt grounding and failure handling, with no network."""
from __future__ import annotations

import pytest

from prahari.ai.assistant import MAX_HISTORY_TURNS, ChatTurn, EditorContext, ask, build_prompt
from prahari.ai.gateway.base import GatewayResponse
from prahari.ai.gateway.null import NullGateway


class RecordingGateway:
    model_id = "test/model:free"
    available = True

    def __init__(self, data=None, error: Exception | None = None):
        self.data = data if data is not None else {"text": "Use `strncpy`."}
        self.error = error
        self.calls: list[tuple[str, str, dict | None]] = []

    def complete(self, system, user, schema=None, temperature=0.0):
        self.calls.append((system, user, schema))
        if self.error:
            raise self.error
        return GatewayResponse(data=self.data, model=self.model_id)


def test_prompt_carries_file_selection_findings_and_question():
    context = EditorContext(
        path="C:/secret/project/main.c",
        language="c",
        text="int main(void) {\n  return 0;\n}",
        selection="return 0;",
        findings=["CWE-416 Use After Free in main() at line 2"],
    )
    prompt = build_prompt("Is this safe?", [], context)
    assert "main.c" in prompt and "secret" not in prompt  # paths redacted by default
    assert "   2 |   return 0;" in prompt  # numbered, so answers can cite lines
    assert "CWE-416" in prompt
    assert prompt.rstrip().endswith("Is this safe?")


def test_history_is_bounded_to_recent_turns():
    history = [ChatTurn("user", f"turn {n}") for n in range(MAX_HISTORY_TURNS + 5)]
    prompt = build_prompt("next", history)
    assert "turn 0" not in prompt
    assert f"turn {MAX_HISTORY_TURNS + 4}" in prompt


def test_ask_returns_text_reply_without_a_schema():
    gateway = RecordingGateway()
    reply = ask(gateway, "How do I fix it?")
    assert reply.reply == "Use `strncpy`." and reply.model == "test/model:free"
    assert gateway.calls[0][2] is None  # free text, not the verdict tool


def test_json_shaped_reply_is_returned_as_code():
    reply = ask(RecordingGateway(data={"a": 1}), "give me json")
    assert reply.reply.startswith("```json")


@pytest.mark.parametrize("question", ["", "   "])
def test_empty_question_is_refused_without_a_request(question):
    gateway = RecordingGateway()
    assert ask(gateway, question).error
    assert gateway.calls == []


def test_unconfigured_gateway_reports_why():
    reply = ask(NullGateway(reason="no API key configured"), "hello")
    assert reply.error == "no API key configured" and not reply.reply


def test_gateway_failure_becomes_an_error_not_an_exception():
    reply = ask(RecordingGateway(error=RuntimeError("quota exhausted")), "hello")
    assert reply.error == "quota exhausted"
