"""Shared HTTP machinery for live gateways.

Retries, backoff, pacing, budget enforcement and thread-safe accounting are
identical whatever the endpoint; only the request shape and the response shape
differ. Keeping the common half here means a second provider costs a request
builder and a response parser rather than a second copy of the logic that
decides when to give up -- and it means a fix to that logic cannot apply to one
provider and not the other.

Subclasses implement four things: :meth:`endpoint`, :meth:`headers`,
:meth:`payload` and :meth:`parse`.

**Rate limits are treated as a budget, not an obstacle.** Free model tiers cap
requests per minute *and* per day, and every retry is a request. So:

* requests are paced client-side (``requests_per_minute``) instead of fired and
  retried, which is what turns a burst into a 429 in the first place;
* a 429 whose reset is seconds away is waited out once, honouring the server's
  ``Retry-After`` or ``X-RateLimit-Reset``;
* a 429 whose reset is far away -- a daily cap -- fails immediately with the
  reset time, because retrying it would only spend the requests that remain.
"""
from __future__ import annotations

import datetime as _dt
import json
import random
import threading
import time
import urllib.error
import urllib.request
from typing import Callable

from .base import GatewayResponse

#: Status codes worth a second attempt: rate limiting, overload, and the
#: transient 5xx family. Anything else is a contract error, and retrying it
#: only wastes the user's quota.
RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504, 529})

#: A 429 that resets further away than this is a quota, not a burst: waiting
#: it out inside an audit is never the right call.
QUOTA_RESET_THRESHOLD_SECONDS = 90.0

#: OpenRouter's stable ``error.metadata.error_type`` values that are worth
#: another attempt. Switching on these is more reliable than reading prose.
TRANSIENT_ERROR_TYPES = frozenset(
    {"rate_limit_exceeded", "provider_overloaded", "provider_unavailable", "timeout", "server"}
)

#: Phrases that mark an upstream error as transient when no error type is given.
TRANSIENT_PHRASES = ("overloaded", "temporarily", "timed out", "timeout", "try again")

#: Where an OpenRouter user changes a privacy policy that excludes free endpoints.
PRIVACY_SETTINGS_URL = "https://openrouter.ai/settings/privacy"

#: ``(url, body, headers, timeout) -> (status, body_bytes, response_headers)``
Transport = Callable[[str, bytes, dict, float], tuple[int, bytes, dict]]


class GatewayError(RuntimeError):
    """Any failure to obtain a verdict. Always recoverable by the caller."""

    def __init__(self, message: str, status: int | None = None, retryable: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class QuotaExhausted(GatewayError):
    """The provider's request quota is spent until ``reset_at``.

    Raised instead of retrying, and remembered by the gateway so every later
    request in the same run fails fast rather than spending one more attempt
    to learn the same thing.
    """

    def __init__(self, message: str, reset_at: float | None = None) -> None:
        super().__init__(message, status=429, retryable=False)
        self.reset_at = reset_at


def urllib_transport(url: str, body: bytes, headers: dict, timeout: float) -> tuple[int, bytes, dict]:
    """The default transport. Never raises for an HTTP status."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:  # a status, not a failure
        return error.code, error.read(), dict(error.headers or {})
    except urllib.error.URLError as error:
        raise GatewayError(f"cannot reach the model endpoint: {error.reason}", retryable=True)
    except TimeoutError:
        raise GatewayError("the model endpoint timed out", retryable=True)


def header(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup; servers disagree on capitalisation."""
    lowered = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == lowered:
            return str(value)
    return None


def reset_epoch(headers: dict, now: float | None = None) -> float | None:
    """When a rate limit resets, as a UNIX timestamp, from whichever header is set.

    ``X-RateLimit-Reset`` arrives in milliseconds on OpenRouter and in seconds
    elsewhere; ``Retry-After`` is a delay. All three are normalised here.
    """
    now = time.time() if now is None else now
    raw = header(headers, "x-ratelimit-reset")
    if raw is not None:
        try:
            value = float(raw)
        except ValueError:
            value = None
        if value is not None:
            if value > 1e11:  # milliseconds since the epoch
                return value / 1000.0
            if value > 1e9:  # seconds since the epoch
                return value
            return now + value  # a relative delay
    retry_after = header(headers, "retry-after")
    if retry_after is not None:
        try:
            return now + float(retry_after)
        except ValueError:
            return None
    return None


class HttpGateway:
    """Synchronous, schema-constrained completions with bounded retries."""

    #: Shown in errors and user agents.
    provider = "http"

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        max_tokens: int = 1024,
        timeout: float = 30.0,
        max_retries: int = 3,
        max_requests: int = 200,
        requests_per_minute: float = 0.0,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        **extra,
    ) -> None:
        if not api_key:
            raise GatewayError("no API key configured")
        self._api_key = api_key
        self.model_id = model
        self.base_url = base_url.rstrip("/")
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_requests = max_requests
        self._transport = transport or urllib_transport
        self._sleep = sleep
        self._clock = clock
        self.extra = extra

        # The adjudicator may run findings concurrently, so the counters that
        # enforce the budget have to be correct under threads rather than
        # approximately correct.
        self._lock = threading.Lock()
        self.requests = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.retries = 0

        #: Seconds between request starts; 0 disables pacing.
        self.min_interval = 60.0 / requests_per_minute if requests_per_minute > 0 else 0.0
        self._pace_lock = threading.Lock()
        self._next_slot = 0.0

        #: The most recent rate-limit headers seen, for reporting.
        self.rate_limit: dict = {}
        #: Set once a quota is exhausted; later calls fail without a request.
        self.quota_exhausted: QuotaExhausted | None = None

    # -- subclass contract ---------------------------------------------------

    def endpoint(self) -> str:
        raise NotImplementedError

    def headers(self) -> dict:
        raise NotImplementedError

    def payload(self, system: str, user: str, schema: dict | None, temperature: float) -> dict:
        raise NotImplementedError

    def parse(self, body: dict, expect_tool: bool) -> tuple[dict, str, dict]:
        """Return ``(verdict, model_id, usage)`` from a successful response."""
        raise NotImplementedError

    def error_detail(self, payload: dict) -> str:
        """Pull a human-readable message out of an error body.

        Routing gateways often say only "Provider returned error" and put the
        upstream's actual reason in ``metadata.raw``; both are kept, because the
        first is useless on its own.
        """
        error = payload.get("error")
        if isinstance(error, dict):
            message = str(error.get("message") or "")
            metadata = error.get("metadata") if isinstance(error.get("metadata"), dict) else {}
            raw = metadata.get("raw")
            if isinstance(raw, str) and raw and raw not in message:
                message = f"{message}: {raw}" if message else raw
            return message[:500]
        if isinstance(error, str):
            return error
        return str(payload.get("message") or "")

    # -- protocol ------------------------------------------------------------

    @property
    def available(self) -> bool:
        return (
            bool(self._api_key)
            and self.requests < self.max_requests
            and self.quota_exhausted is None
        )

    def complete(
        self,
        system: str,
        user: str,
        schema: dict | None = None,
        temperature: float = 0.0,
    ) -> GatewayResponse:
        if self.quota_exhausted is not None:
            raise self.quota_exhausted
        with self._lock:
            over_budget = self.requests >= self.max_requests
        if over_budget:
            raise GatewayError(
                f"request budget exhausted ({self.max_requests}); "
                "raise AEGIS_AI_MAX_REQUESTS to continue"
            )

        body, latency_ms = self._post(
            self.endpoint(), self.payload(system, user, schema, temperature)
        )

        verdict, model, usage = self.parse(body, expect_tool=schema is not None)
        with self._lock:
            self.input_tokens += int(usage.get("input_tokens") or 0)
            self.output_tokens += int(usage.get("output_tokens") or 0)

        return GatewayResponse(
            data=verdict,
            model=model or self.model_id,
            cached=False,
            latency_ms=round(latency_ms, 2),
            raw=json.dumps(body, sort_keys=True),
            usage=usage,
        )

    # -- pacing --------------------------------------------------------------

    def _pace(self) -> None:
        """Reserve the next request slot, sleeping until it arrives.

        Slots are reserved under a lock and slept outside it, so concurrent
        workers queue in order without holding each other up for longer than
        the interval itself.
        """
        if not self.min_interval:
            return
        with self._pace_lock:
            now = self._clock()
            start = max(now, self._next_slot)
            self._next_slot = start + self.min_interval
        wait = start - now
        if wait > 0:
            self._sleep(wait)

    # -- transport with bounded retries -------------------------------------

    def _post(self, path: str, payload: dict) -> tuple[dict, float]:
        """POST with retries. Returns the body and the time spent on the wire.

        The latency excludes client-side pacing and backoff sleeps: it is a
        measurement of the provider, which is what the benchmark compares.
        """
        url = f"{self.base_url}{path}"
        body = json.dumps(payload).encode("utf-8")
        headers = self.headers()
        last: GatewayError | None = None
        wire_ms = 0.0

        for attempt in range(self.max_retries + 1):
            self._pace()
            with self._lock:
                self.requests += 1
            sent = time.perf_counter()
            try:
                status, raw, response_headers = self._transport(url, body, headers, self.timeout)
                wire_ms += (time.perf_counter() - sent) * 1000.0
            except GatewayError as error:
                wire_ms += (time.perf_counter() - sent) * 1000.0
                last = error
                if not error.retryable or attempt == self.max_retries:
                    raise
                with self._lock:
                    self.retries += 1
                self._sleep(self._backoff(attempt, {}))
                continue

            self._record_rate_limit(response_headers)

            if status == 200:
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise GatewayError(
                        f"malformed response body: {error}{self.context()}", status=status
                    )
                # Some gateways report upstream failures inside a 200 body. The
                # embedded classification decides whether another attempt is
                # worth it: an overloaded upstream is transient, a rejected
                # request is not.
                if isinstance(decoded, dict) and decoded.get("error"):
                    last = self.embedded_error(decoded)
                    if not last.retryable or attempt == self.max_retries:
                        raise last
                    with self._lock:
                        self.retries += 1
                    self._sleep(self._backoff(attempt, response_headers))
                    continue
                return decoded, round(wire_ms, 2)

            if status == 429:
                quota = self._quota_error(raw, response_headers)
                if quota is not None:
                    self.quota_exhausted = quota
                    raise quota

            last = self.status_error(status, raw)
            if not last.retryable or attempt == self.max_retries:
                raise last
            with self._lock:
                self.retries += 1
            self._sleep(self._backoff(attempt, response_headers))

        raise last or GatewayError("request failed")  # pragma: no cover - unreachable

    def _record_rate_limit(self, headers: dict) -> None:
        limit = header(headers, "x-ratelimit-limit")
        remaining = header(headers, "x-ratelimit-remaining")
        if limit is None and remaining is None:
            return
        self.rate_limit = {
            "limit": limit,
            "remaining": remaining,
            "reset_at": reset_epoch(headers),
        }

    def _quota_error(self, raw: bytes, headers: dict) -> QuotaExhausted | None:
        """A 429 that will not clear within an audit is a quota: report it."""
        reset_at = reset_epoch(headers)
        if reset_at is None:
            return None
        seconds = reset_at - time.time()
        if seconds <= QUOTA_RESET_THRESHOLD_SECONDS:
            return None
        try:
            detail = self.error_detail(json.loads(raw.decode("utf-8")))
        except Exception:
            detail = ""
        when = _dt.datetime.fromtimestamp(reset_at, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        message = f"{self.provider} request quota exhausted; it resets at {when}"
        if detail:
            message = f"{message} ({detail})"
        return QuotaExhausted(message, reset_at=reset_at)

    def context(self) -> str:
        """Extra detail appended to every error message; subclasses add routing."""
        return ""

    def hint(self, detail: str) -> str:
        """Name the fix when a refusal is about policy rather than load."""
        lowered = detail.lower()
        if "agentic harness" in lowered:
            return (
                " -- this free endpoint is reserved for agent apps listed on OpenRouter; "
                "choose another free model (aegis ai --models)"
            )
        if "data policy" in lowered or "privacy" in lowered:
            return (
                " -- the account's privacy settings exclude this free endpoint; "
                f"allow free endpoints at {PRIVACY_SETTINGS_URL}"
            )
        return ""

    @staticmethod
    def _error_type(payload: dict) -> str:
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        metadata = error.get("metadata") if isinstance(error.get("metadata"), dict) else {}
        return str(metadata.get("error_type") or "")

    def embedded_error(self, payload: dict) -> GatewayError:
        """Classify an error delivered inside a successful HTTP response."""
        detail = self.error_detail(payload)
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        try:
            code = int(error.get("code"))
        except (TypeError, ValueError):
            code = None
        transient = (
            code in RETRYABLE_STATUS
            or self._error_type(payload) in TRANSIENT_ERROR_TYPES
            or any(phrase in detail.lower() for phrase in TRANSIENT_PHRASES)
        )
        return GatewayError(
            f"the provider reported an error: {detail}{self.hint(detail)}{self.context()}",
            status=code or 200,
            retryable=transient,
        )

    def status_error(self, status: int, raw: bytes) -> GatewayError:
        """Turn a non-200 into a message a user can act on."""
        try:
            detail = self.error_detail(json.loads(raw.decode("utf-8")))
        except Exception:
            detail = raw.decode("utf-8", errors="replace")[:200]

        if status == 401:
            message = "the API key was rejected (401); check OPENROUTER_API_KEY / AEGIS_API_KEY in .env"
        elif status == 402:
            message = "the account has no credit for this request (402)"
        elif status == 403:
            message = "the API key is not permitted to use this model (403)"
        elif status == 404:
            message = f"unknown model or endpoint (404): {detail or 'no detail'}"
        elif status == 429:
            message = "rate limited by the model endpoint (429)"
        else:
            message = f"model endpoint returned {status}"
        if detail and status not in (401, 404):
            message = f"{message}: {detail}"
        message = f"{message}{self.hint(detail)}{self.context()}"
        return GatewayError(message, status=status, retryable=status in RETRYABLE_STATUS)

    def _backoff(self, attempt: int, headers: dict) -> float:
        """Exponential backoff, honouring the server's reset hint when it gives one.

        Jitter matters more than it looks: an audit adjudicates many findings,
        so a synchronised retry storm is the realistic failure mode rather than
        a hypothetical one.
        """
        retry_after = header(headers, "retry-after")
        if retry_after is not None:
            try:
                return max(0.0, min(float(retry_after), 60.0))
            except ValueError:
                pass
        reset_at = reset_epoch(headers)
        if reset_at is not None:
            return max(0.0, min(reset_at - time.time(), 60.0))
        return min(2.0**attempt, 16.0) * (0.5 + random.random() / 2.0)


def parse_json_object(text: str) -> dict | None:
    """Best-effort JSON extraction from text, including fenced code blocks."""
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.split("```")[1] if "```" in candidate[3:] else candidate[3:]
        if candidate.lstrip().startswith("json"):
            candidate = candidate.lstrip()[4:]
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        value = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None
