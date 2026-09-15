"""A deterministic stand-in for the model endpoint.

Unit tests inject a fake transport, which proves the gateway's logic but stops
short of the socket. This serves the same API over real HTTP, so the whole live
path -- configuration, factory, request construction, TLS-less transport,
tool-use parsing, clamping, reporting -- can be exercised with no credential and
no network:

    $ python eval/mock_model.py &
    $ PRAHARI_API_KEY=mock PRAHARI_API_BASE=http://127.0.0.1:8787 \\
          prahari audit examples --adjudicate

It answers both API shapes -- Anthropic's ``/v1/messages`` and the OpenAI
``/chat/completions`` that OpenRouter serves -- so either gateway can be pointed
at it and the two compared against the same answers.

Its verdicts are a fixed rule, not a model: a path whose guards mention a
length check is dismissed, everything else stands. That makes it useless as an
oracle and ideal as a test fixture -- the same input always produces the same
output, so a CI run that uses it stays reproducible.

It is not a mock of the *judgement*. Nothing here should be read as evidence
about what a real model would say; the evaluation reports the NullGateway
control row for exactly that reason.
"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

#: Guards that plausibly neutralise a flow. Matching on these is a deliberately
#: crude rule; its only job is to be deterministic and to exercise both
#: branches of the adjudicator.
_NEUTRALISING = re.compile(r"\b(strlen|sizeof|snprintf|isalnum|allowlist|whitelist)\b", re.I)

FAILURE_MODES = {"rate_limit": 429, "server_error": 503, "bad_key": 401}


def verdict_for(prompt: str) -> dict:
    """The fixed rule, applied to a slice."""
    guards = ""
    if "GUARDS ON PATH:" in prompt:
        guards = prompt.split("GUARDS ON PATH:", 1)[1]

    if _NEUTRALISING.search(guards):
        return {
            "exploitable": False,
            "confidence": 0.8,
            "reason": "a guard on the path constrains the value before it reaches the sink",
            "missing_control": "",
        }
    return {
        "exploitable": True,
        "confidence": 0.9,
        "reason": "no guard on the path constrains the value reaching the sink",
        "missing_control": "input validation before the sink",
    }


class Handler(BaseHTTPRequestHandler):
    """Speaks just enough of both API shapes to answer a forced tool call.

    ``/v1/messages`` is Anthropic's; ``/chat/completions`` is the OpenAI shape
    OpenRouter serves. Both are answered from the same rule, so a test can
    point either gateway at this server and compare like with like.
    """

    #: Set by :func:`serve` to make the server return errors instead, so retry
    #: and degradation paths can be demonstrated rather than described.
    failure_mode: str | None = None
    #: Answer in plain content instead of a tool call, to exercise the fallback
    #: every model without tool support will take.
    no_tool_calls = False
    requests_served = 0

    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - name fixed by the base class
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).requests_served += 1

        authorised = self.headers.get("x-api-key") or self.headers.get("authorization")
        if not authorised:
            self._send(401, {"error": {"message": "missing credentials"}})
            return

        path = self.path.rstrip("/")
        if path.endswith("/chat/completions"):
            shape = "openai"
        elif path.endswith("/v1/messages"):
            shape = "anthropic"
        else:
            self._send(404, {"error": {"message": f"unknown path {self.path}"}})
            return
        if self.failure_mode in FAILURE_MODES:
            self._send(
                FAILURE_MODES[self.failure_mode],
                {"error": {"message": f"mock failure: {self.failure_mode}"}},
            )
            return

        prompt = "".join(
            message.get("content", "") if isinstance(message.get("content"), str) else ""
            for message in body.get("messages", [])
        )
        verdict = verdict_for(prompt)
        # With fallbacks the request names a list instead of one model; the
        # first entry is the one that answers when nothing has failed.
        model = body.get("model") or (body.get("models") or ["mock-model"])[0]
        tokens = max(1, len(prompt) // 4)

        if shape == "openai":
            self._send(200, self._openai_body(body, verdict, model, tokens))
        else:
            self._send(200, self._anthropic_body(body, verdict, model, tokens))

    def _anthropic_body(self, request: dict, verdict: dict, model: str, tokens: int) -> dict:
        tool = (request.get("tools") or [{}])[0].get("name", "record_verdict")
        return {
            "id": "msg_mock",
            "model": model,
            "stop_reason": "tool_use",
            "content": [
                {"type": "tool_use", "id": "tu_mock", "name": tool, "input": verdict}
            ],
            "usage": {"input_tokens": tokens, "output_tokens": 48},
        }

    def _openai_body(self, request: dict, verdict: dict, model: str, tokens: int) -> dict:
        """The OpenAI shape, including the detail that trips people up.

        ``arguments`` is a JSON *string*, not an object. A gateway that forgets
        to parse it fails here rather than in production.
        """
        function = (request.get("tools") or [{}])[0].get("function") or {}
        name = function.get("name", "record_verdict")
        if self.no_tool_calls:
            message = {"role": "assistant", "content": json.dumps(verdict)}
        else:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_mock",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(verdict)},
                    }
                ],
            }
        return {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
            "usage": {
                "prompt_tokens": tokens,
                "completion_tokens": 48,
                "total_tokens": tokens + 48,
            },
        }

    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args) -> None:  # keep the harness output readable
        pass


def serve(
    port: int = 8787,
    failure_mode: str | None = None,
    no_tool_calls: bool = False,
) -> HTTPServer:
    """Start the server on a background thread and return it."""
    Handler.failure_mode = failure_mode
    Handler.no_tool_calls = no_tool_calls
    Handler.requests_served = 0
    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> None:  # pragma: no cover - manual use
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--fail", choices=sorted(FAILURE_MODES), help="return errors instead")
    parser.add_argument(
        "--no-tool-calls",
        action="store_true",
        help="answer in plain content, as a model without tool support would",
    )
    args = parser.parse_args()

    server = serve(args.port, args.fail, args.no_tool_calls)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"mock model endpoint on {base}")
    print("  Anthropic shape:  POST /v1/messages")
    print("  OpenAI shape:     POST /chat/completions")
    print(f"  PRAHARI_API_KEY=mock PRAHARI_API_BASE={base} prahari audit examples --adjudicate")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":  # pragma: no cover
    main()
