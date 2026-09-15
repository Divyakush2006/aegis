"""The Anthropic gateway: the Messages API.

Two decisions worth stating, because each one is a deliberate trade:

**No SDK.** The request is one JSON POST, so it is made with the standard
library. Adding a vendored HTTP client and its transitive dependencies to a
compiler in order to send a single request is a cost with no matching benefit,
and it would make the analysis core -- which needs no network at all -- harder
to install. ``transport`` is injectable, so the tests exercise every branch of
this file without a socket.

**Structured output via tool use, not prompt instructions.** Asking a model to
"respond only in JSON" produces JSON most of the time; declaring a tool whose
``input_schema`` *is* the verdict schema produces an object the API itself
validated. A parse failure here is a bug in the contract, not a bad day, so it
raises rather than guessing.

Retries, backoff and budget live in :mod:`aegis.ai.gateway.http`, shared with
every other provider.
"""
from __future__ import annotations

from .http import (  # re-exported: these are part of this module's public surface
    GatewayError,
    HttpGateway,
    Transport,
    parse_json_object,
    urllib_transport,
)

#: Name of the tool the model is forced to call. Its schema is the caller's
#: verdict schema, so the response is structurally guaranteed.
VERDICT_TOOL = "record_verdict"

DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_API_VERSION = "2023-06-01"

__all__ = [
    "AnthropicGateway",
    "GatewayError",
    "Transport",
    "VERDICT_TOOL",
    "urllib_transport",
]


class AnthropicGateway(HttpGateway):
    """Anthropic Messages API, with the verdict tool forced."""

    provider = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-5",
        base_url: str = DEFAULT_BASE_URL,
        api_version: str = DEFAULT_API_VERSION,
        **kwargs,
    ) -> None:
        super().__init__(api_key=api_key, model=model, base_url=base_url, **kwargs)
        self.api_version = api_version

    def endpoint(self) -> str:
        return "/v1/messages"

    def headers(self) -> dict:
        return {
            "content-type": "application/json",
            "accept": "application/json",
            "x-api-key": self._api_key,
            "anthropic-version": self.api_version,
            "user-agent": "aegis-compiler/0.1.0",
        }

    def payload(self, system: str, user: str, schema: dict | None, temperature: float) -> dict:
        payload: dict = {
            "model": self.model_id,
            "max_tokens": self.max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if schema is not None:
            # Forcing the tool is what makes the reply an object rather than
            # prose that happens to contain an object.
            payload["tools"] = [
                {
                    "name": VERDICT_TOOL,
                    "description": "Record the exploitability verdict for the candidate path.",
                    "input_schema": schema,
                }
            ]
            payload["tool_choice"] = {"type": "tool", "name": VERDICT_TOOL}
        return payload

    def parse(self, body: dict, expect_tool: bool) -> tuple[dict, str, dict]:
        usage = body.get("usage") or {}
        return (
            _extract_verdict(body, expect_tool),
            body.get("model") or self.model_id,
            {
                "input_tokens": int(usage.get("input_tokens") or 0),
                "output_tokens": int(usage.get("output_tokens") or 0),
                "stop_reason": body.get("stop_reason", ""),
            },
        )


def _extract_verdict(body: dict, expect_tool: bool) -> dict:
    """Pull the structured verdict out of a Messages API response.

    The forced tool call is the expected shape. The text fallback exists for
    the schema-less case and for a model that answers in prose despite the
    tool choice; it is not a licence to accept anything, so a response with
    neither shape raises.
    """
    content = body.get("content") or []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            value = block.get("input")
            if isinstance(value, dict):
                return value

    text = "".join(
        block.get("text", "")
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    ).strip()

    if text:
        parsed = parse_json_object(text)
        if parsed is not None:
            return parsed
        if not expect_tool:
            return {"text": text}

    raise GatewayError(
        f"response contained no structured verdict (stop_reason={body.get('stop_reason')!r})"
    )


#: Retained for callers that imported it from this module before the shared
#: HTTP layer existed.
_parse_json_object = parse_json_object
