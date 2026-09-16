"""Prahari AI: the IDE's conversational assistant.

Adjudication (``adjudicator.py``) asks a model one narrow, structured question
per finding and may only demote. The assistant is the other half of an AI IDE:
free-form questions about the file in front of the developer. It is grounded
the same way -- the prompt carries the open file and, for C, the compiler's own
findings -- so "is this safe?" is answered against what the analyses proved
rather than against the model's impression of the code.

It shares the gateway, the free-only policy and the key handling with
adjudication, and adds no provider code of its own.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePath

from .gateway.base import ModelGateway

#: How much of the open file is sent. Large enough for any file a person reads
#: in one sitting; a generated 50k-line file is truncated around the cursor's
#: selection rather than sent whole to a free-tier context window.
MAX_FILE_CHARS = 24_000
#: Earlier turns carried forward, so a follow-up can say "and that function?".
MAX_HISTORY_TURNS = 8
MAX_TURN_CHARS = 4_000

SYSTEM_PROMPT = """\
You are Prahari AI, the assistant built into Prahari IDE -- a development \
environment around a security-aware C compiler whose dataflow analyses detect \
CWE-78, CWE-120, CWE-134, CWE-476, CWE-415, CWE-416 and CWE-401.

Help the developer with the code they have open: explain it, find bugs, suggest \
fixes, write code and answer programming questions in any language.

Rules:
- Answer in GitHub-flavoured Markdown. Put code in fenced blocks with a language tag.
- Be concise and concrete; refer to line numbers when you discuss the open file.
- When compiler findings are provided, they were proven by static analysis along \
the path shown. Treat them as facts about the code, explain them plainly, and \
propose a fix that removes the path. Do not claim a finding is absent or wrong \
unless the code shown clearly contradicts it, and say why.
- If the question cannot be answered from the context, say what is missing.
"""


@dataclass
class ChatTurn:
    role: str  # "user" or "assistant"
    content: str


@dataclass
class EditorContext:
    """What the developer is looking at. Every field is optional."""

    path: str = ""
    language: str = ""
    text: str = ""
    selection: str = ""
    findings: list[str] = field(default_factory=list)


@dataclass
class ChatReply:
    reply: str = ""
    model: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {"reply": self.reply, "model": self.model, "error": self.error}


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    return f"{text[:head]}\n... [{len(text) - limit} characters omitted] ...\n{text[-tail:]}"


def _numbered(text: str) -> str:
    return "\n".join(f"{number:>4} | {line}" for number, line in enumerate(text.splitlines(), 1))


def build_prompt(
    question: str,
    history: Iterable[ChatTurn] = (),
    context: EditorContext | None = None,
    redact_paths: bool = True,
) -> str:
    """Assemble the user message: context first, then conversation, then question."""
    parts: list[str] = []
    context = context or EditorContext()

    if context.path or context.text:
        name = PurePath(context.path).name if redact_paths else context.path
        language = f" ({context.language})" if context.language else ""
        parts.append(f"## Open file: {name or 'untitled'}{language}")
        if context.text:
            parts.append("```\n" + _numbered(_clip(context.text, MAX_FILE_CHARS)) + "\n```")
    if context.selection.strip():
        parts.append("## Selected text\n```\n" + _clip(context.selection, MAX_TURN_CHARS) + "\n```")
    if context.findings:
        parts.append("## Prahari compiler findings for this file")
        parts.extend(f"- {finding}" for finding in context.findings)

    turns = [turn for turn in history if turn.content.strip()][-MAX_HISTORY_TURNS:]
    if turns:
        parts.append("## Conversation so far")
        for turn in turns:
            speaker = "Developer" if turn.role == "user" else "Prahari AI"
            parts.append(f"**{speaker}:** {_clip(turn.content, MAX_TURN_CHARS)}")

    parts.append("## Question\n" + question.strip())
    return "\n\n".join(parts)


def _text_of(data: dict) -> str:
    """The reply text, whatever shape the gateway decoded it into."""
    if isinstance(data.get("text"), str):
        return data["text"]
    # A reply that happened to be a JSON object was decoded by the gateway; the
    # developer asked a question, so give them back what the model wrote.
    import json

    return "```json\n" + json.dumps(data, indent=2) + "\n```"


def ask(
    gateway: ModelGateway,
    question: str,
    history: Iterable[ChatTurn] = (),
    context: EditorContext | None = None,
    redact_paths: bool = True,
) -> ChatReply:
    """One conversational turn. Never raises: failures become ``error``."""
    if not question.strip():
        return ChatReply(error="ask a question first")
    # NullGateway is "available" by design -- it answers adjudication with a
    # fixed, honest non-verdict -- but it has nothing to say in a conversation.
    if getattr(gateway, "model_id", "") == "null" or not gateway.available:
        reason = getattr(gateway, "reason", "") or "no model is configured"
        return ChatReply(error=reason)
    try:
        response = gateway.complete(
            SYSTEM_PROMPT,
            build_prompt(question, history, context, redact_paths),
            schema=None,
            temperature=0.2,
        )
    except Exception as error:  # a chat panel must show the failure, not crash
        return ChatReply(model=getattr(gateway, "model_id", ""), error=str(error))
    text = _text_of(response.data).strip()
    if not text:
        return ChatReply(model=response.model, error="the model returned an empty reply")
    return ChatReply(reply=text, model=response.model)
