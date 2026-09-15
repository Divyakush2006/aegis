"""The OpenRouter gateway: one key, many models.

OpenRouter speaks the OpenAI chat-completions shape and routes to whichever
model the request names, so a single credential reaches models from many labs.
For this project that is worth more than it looks: the adjudication experiment
the evaluation describes -- *does a second opinion help, and which one* --
becomes a loop over model ids rather than a loop over vendor integrations.

Differences from the Anthropic path, all handled here:

* ``POST /chat/completions`` with a ``Bearer`` token rather than ``x-api-key``.
* The system prompt is a message with ``role: "system"``, not a top-level field.
* Structured output is an OpenAI *function* tool, and the arguments come back
  as a **JSON string** that has to be parsed, not as an object.
* Not every model supports tool calling. When one does not, the verdict arrives
  as ordinary message content, so the text path here is a first-class fallback
  -- and ``tool_call_responses`` / ``prose_responses`` record which path was
  taken.

Two OpenRouter features are used deliberately:

* **Fallbacks.** With ``fallback_models`` set, the request carries a ``models``
  list and OpenRouter moves to the next entry on rate limiting or downtime. The
  model that actually answered is reported in the response and recorded in
  ``routed_models``, so a verdict is always attributable.
* **Reasoning effort.** Free frontier models are reasoning models. The
  ``reasoning.effort`` hint trades depth for time per use case, and
  ``exclude`` keeps the reasoning text out of the response: the adjudicator
  needs the verdict, not the transcript.

Retries, pacing, quotas and budget live in :mod:`prahari.ai.gateway.http`.
"""
from __future__ import annotations

from .http import GatewayError, HttpGateway, parse_json_object

VERDICT_TOOL = "record_verdict"

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
#: The free review model; see ``prahari.ai.config.PROVIDER_DEFAULTS``.
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"

#: Sent so the request is attributable on the OpenRouter dashboard. Both are
#: optional to the API and carry no user data.
REFERER = "https://github.com/Divyakush2006/prahari"
TITLE = "Prahari Compiler"

__all__ = ["OpenRouterGateway", "GatewayError", "DEFAULT_MODEL", "DEFAULT_BASE_URL"]


class OpenRouterGateway(HttpGateway):
    """OpenAI-compatible chat completions, routed by OpenRouter."""

    provider = "openrouter"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        referer: str = REFERER,
        title: str = TITLE,
        require_tools: bool = False,
        fallback_models: tuple[str, ...] | list[str] = (),
        reasoning_effort: str = "",
        **kwargs,
    ) -> None:
        super().__init__(api_key=api_key, model=model, base_url=base_url, **kwargs)
        self.referer = referer
        self.title = title
        #: When True, a model that answers in prose instead of calling the tool
        #: is an error. Left False by default so a model without tool support
        #: still returns a usable verdict.
        self.require_tools = require_tools
        self.fallback_models = tuple(m for m in fallback_models if m and m != model)
        self.reasoning_effort = reasoning_effort
        #: Set once a response arrives: True if the verdict came from a tool
        #: call, False if it was parsed out of message content.
        self.used_tool_call: bool | None = None
        #: Running counts of each path, for the benchmark's TOOLS column.
        self.tool_call_responses = 0
        self.prose_responses = 0
        #: Which model answered, and how often -- differs from ``model_id``
        #: only when a fallback was used.
        self.routed_models: dict[str, int] = {}

    def endpoint(self) -> str:
        return "/chat/completions"

    def context(self) -> str:
        # With fallbacks, OpenRouter reports only the last model's error. Naming
        # the whole chain is what makes "Nvidia is overloaded" legible when the
        # configured model was not an Nvidia one.
        if not self.fallback_models:
            return ""
        chain = ", ".join((self.model_id, *self.fallback_models))
        return f" [models tried in order: {chain}]"

    def headers(self) -> dict:
        return {
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": f"Bearer {self._api_key}",
            # Attribution headers OpenRouter uses for its rankings. Optional,
            # and deliberately generic -- no user or repository data.
            "http-referer": self.referer,
            "x-title": self.title,
            "user-agent": "prahari-compiler/0.1.0",
        }

    def payload(self, system: str, user: str, schema: dict | None, temperature: float) -> dict:
        payload: dict = {
            "max_tokens": self.max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self.fallback_models:
            # OpenRouter tries these in order; ``model`` is not sent alongside,
            # so there is exactly one statement of the routing intent.
            payload["models"] = [self.model_id, *self.fallback_models]
        else:
            payload["model"] = self.model_id
        if self.reasoning_effort:
            payload["reasoning"] = {"effort": self.reasoning_effort, "exclude": True}
        if schema is not None:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": VERDICT_TOOL,
                        "description": (
                            "Record the exploitability verdict for the candidate path."
                        ),
                        "parameters": schema,
                    },
                }
            ]
            payload["tool_choice"] = {"type": "function", "function": {"name": VERDICT_TOOL}}
        return payload

    def parse(self, body: dict, expect_tool: bool) -> tuple[dict, str, dict]:
        choices = body.get("choices") or []
        if not choices:
            raise GatewayError(f"response contained no choices (id={body.get('id')!r})")

        message = (choices[0] or {}).get("message") or {}
        finish = (choices[0] or {}).get("finish_reason", "")

        verdict = _from_tool_call(message)
        used_tool = verdict is not None
        if verdict is None:
            verdict = _from_content(message, expect_tool, self.require_tools, finish)

        answered = body.get("model") or self.model_id
        with self._lock:
            self.used_tool_call = used_tool
            if used_tool:
                self.tool_call_responses += 1
            else:
                self.prose_responses += 1
            self.routed_models[answered] = self.routed_models.get(answered, 0) + 1

        usage = body.get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        return (
            verdict,
            answered,
            {
                # Normalised to the same names every gateway reports, so the
                # adjudicator's accounting does not need to know the provider.
                "input_tokens": int(usage.get("prompt_tokens") or 0),
                "output_tokens": int(usage.get("completion_tokens") or 0),
                "reasoning_tokens": int(details.get("reasoning_tokens") or 0),
                "stop_reason": finish,
                "used_tool_call": used_tool,
                "fallback_used": answered != self.model_id,
            },
        )


def _from_tool_call(message: dict) -> dict | None:
    """The expected shape: arguments arrive as a JSON *string*."""
    for call in message.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        function = call.get("function") or {}
        arguments = function.get("arguments")
        if isinstance(arguments, dict):  # some routes pre-decode it
            return arguments
        if isinstance(arguments, str):
            parsed = parse_json_object(arguments)
            if parsed is not None:
                return parsed
            raise GatewayError(
                f"tool call arguments were not valid JSON: {arguments[:160]!r}"
            )
    return None


def _from_content(message: dict, expect_tool: bool, require_tools: bool, finish: str = "") -> dict:
    """Fallback for models that answer in prose rather than calling the tool."""
    if require_tools:
        raise GatewayError(
            "the model did not call the verdict tool and require_tools is set; "
            "choose a model with tool support or clear the flag"
        )

    content = message.get("content")
    if isinstance(content, list):  # some routes return content blocks
        content = "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") in (None, "text")
        )
    text = (content or "").strip()

    if text:
        parsed = parse_json_object(text)
        if parsed is not None:
            return parsed
        if not expect_tool:
            return {"text": text}

    if finish == "length":
        # A reasoning model that thinks past max_tokens never reaches the tool
        # call. Saying so turns a baffling "no verdict" into a setting to change.
        raise GatewayError(
            "the model ran out of tokens before answering (finish_reason=length); "
            "raise PRAHARI_AI_MAX_TOKENS or lower PRAHARI_AI_REASONING"
        )
    raise GatewayError(
        "response contained no structured verdict: the model neither called the "
        "tool nor returned parseable JSON"
    )
