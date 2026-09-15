"""The free-tier guarantees: free-only models, per-use-case roles, and quotas.

Aegis runs on free models with a daily request cap. That makes three properties
load-bearing rather than nice to have, and each is tested here without a key:

* a non-free model id is refused before any request exists;
* the review and interactive use cases resolve their own models, while sharing
  every guarantee;
* rate limits are spent carefully -- paced before they trip, waited out when
  they clear in seconds, and failed fast when they will not clear today.
"""
from __future__ import annotations

import json
import time

import pytest

from aegis.ai.adjudicator import SYSTEM_PROMPT, VERDICT_SCHEMA, Adjudicator
from aegis.ai.config import PROVIDER_DEFAULTS, AIConfig, is_free_model, load_config
from aegis.ai.gateway import build_gateway
from aegis.ai.gateway.http import QuotaExhausted, header, reset_epoch
from aegis.ai.gateway.null import NullGateway
from aegis.ai.gateway.openrouter import OpenRouterGateway

KEY = {"OPENROUTER_API_KEY": "sk-or-v1-test", "AEGIS_AI_CACHE": "0"}


def completion(model="thinkingmachines/inkling:free"):
    verdict = {"exploitable": True, "confidence": 0.8, "reason": "unguarded"}
    return {
        "model": model,
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {"name": "record_verdict", "arguments": json.dumps(verdict)},
                        }
                    ]
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20},
    }


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, url, body, headers, timeout):
        self.requests.append(json.loads(body))
        status, payload, response_headers = (
            self.responses.pop(0) if self.responses else (200, completion(), {})
        )
        return status, json.dumps(payload).encode(), response_headers


def gateway(*responses, **kwargs):
    transport = Transport(*responses)
    kwargs.setdefault("sleep", lambda _s: None)
    instance = OpenRouterGateway(api_key="sk-or-v1-test", transport=transport, **kwargs)
    instance.transport = transport
    return instance


def ask(instance):
    return instance.complete(system=SYSTEM_PROMPT, user="CANDIDATE", schema=VERDICT_SCHEMA)


# --- free-only --------------------------------------------------------------


class TestFreeOnly:
    def test_every_default_openrouter_model_is_free(self):
        defaults = PROVIDER_DEFAULTS["openrouter"]
        models = [defaults["model"], defaults["interactive_model"], *defaults["fallback_models"]]
        assert all(is_free_model(m) for m in models), models
        assert defaults["free_only"] is True

    def test_free_only_is_on_for_an_openrouter_key(self, tmp_path):
        config = load_config(start=tmp_path, environ=KEY)
        assert config.free_only is True
        assert config.free_only_violations() == []

    def test_a_paid_review_model_is_refused_before_any_request(self, tmp_path):
        config = load_config(start=tmp_path, environ={**KEY, "AEGIS_MODEL": "openai/gpt-5"})
        built = build_gateway(config)
        assert isinstance(built, NullGateway)
        assert "openai/gpt-5" in built.reason and ":free" in built.reason

    def test_a_paid_interactive_model_is_refused_too(self, tmp_path):
        config = load_config(
            start=tmp_path, environ={**KEY, "AEGIS_MODEL_INTERACTIVE": "anthropic/claude-x"}
        )
        assert isinstance(build_gateway(config), NullGateway)

    def test_a_paid_fallback_is_refused_too(self, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={**KEY, "AEGIS_MODEL_FALLBACKS": "poolside/laguna-s-2.1:free, x/paid"},
        )
        built = build_gateway(config)
        assert isinstance(built, NullGateway) and "x/paid" in built.reason

    def test_the_router_without_a_free_suffix_is_refused(self):
        # openrouter/free picks a random model per request, which would make
        # verdicts irreproducible; it is refused by the same rule.
        assert is_free_model("openrouter/free") is False

    def test_free_only_can_be_switched_off_explicitly(self, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={**KEY, "AEGIS_MODEL": "openai/gpt-5", "AEGIS_AI_FREE_ONLY": "0"},
        )
        assert isinstance(build_gateway(config), OpenRouterGateway)

    def test_the_refusal_reaches_the_adjudication_report(self, audit, tmp_path):
        config = load_config(start=tmp_path, environ={**KEY, "AEGIS_MODEL": "openai/gpt-5"})
        adjudicator = Adjudicator(build_gateway(config))
        assert adjudicator.enabled is False
        index = audit("cmd_injection.c")
        before = len(index.findings)
        adjudicator.run(index)
        assert len(index.findings) == before


# --- roles ------------------------------------------------------------------


class TestRoles:
    def test_review_and_interactive_resolve_different_models(self, tmp_path):
        review = load_config(start=tmp_path, environ=KEY)
        interactive = load_config(start=tmp_path, environ=KEY, role="interactive")
        defaults = PROVIDER_DEFAULTS["openrouter"]
        assert review.model == defaults["model"]
        assert interactive.model == defaults["interactive_model"]
        assert review.reasoning_effort == "medium"
        assert interactive.reasoning_effort == "low"
        assert interactive.role == "interactive"

    def test_roles_share_every_guarantee(self, tmp_path):
        review = load_config(start=tmp_path, environ=KEY)
        interactive = review.for_role("interactive")
        for attribute in ("api_key", "free_only", "fallback_models", "max_requests",
                          "requests_per_minute", "redact_paths"):
            assert getattr(review, attribute) == getattr(interactive, attribute)

    def test_interactive_falls_back_to_the_review_model_when_unset(self):
        config = AIConfig(model="a:free", reasoning_effort="high")
        interactive = config.for_role("interactive")
        assert interactive.model == "a:free"
        assert interactive.reasoning_effort == "high"

    def test_an_unknown_role_is_an_error(self):
        with pytest.raises(ValueError, match="unknown role"):
            AIConfig().for_role("summarise")

    def test_fallbacks_parse_from_a_comma_list(self, tmp_path):
        config = load_config(
            start=tmp_path, environ={**KEY, "AEGIS_MODEL_FALLBACKS": " a:free ,b:free,, "}
        )
        assert config.fallback_models == ("a:free", "b:free")
        assert config.models_in_order()[1:] == ["a:free", "b:free"]

    def test_an_invalid_reasoning_effort_keeps_the_default(self, tmp_path):
        config = load_config(start=tmp_path, environ={**KEY, "AEGIS_AI_REASONING": "extreme"})
        assert config.reasoning_effort == "medium"

    def test_describe_names_both_roles_and_no_secret(self, tmp_path):
        described = load_config(start=tmp_path, environ=KEY).describe()
        assert described["model"] and described["interactive_model"]
        assert described["reasoning_effort"] != described["interactive_reasoning_effort"]
        assert described["free_only"] is True
        assert "sk-or-v1-test" not in json.dumps(described)


# --- the request ------------------------------------------------------------


class TestPayload:
    def test_fallbacks_are_sent_as_an_ordered_models_list(self):
        instance = gateway(fallback_models=("b:free", "c:free"), model="a:free")
        ask(instance)
        payload = instance.transport.requests[0]
        assert payload["models"] == ["a:free", "b:free", "c:free"]
        assert "model" not in payload

    def test_without_fallbacks_a_single_model_is_sent(self):
        instance = gateway(model="a:free")
        ask(instance)
        payload = instance.transport.requests[0]
        assert payload["model"] == "a:free" and "models" not in payload

    def test_reasoning_effort_is_sent_and_its_text_excluded(self):
        instance = gateway(reasoning_effort="low")
        ask(instance)
        assert instance.transport.requests[0]["reasoning"] == {"effort": "low", "exclude": True}

    def test_no_reasoning_field_when_unset(self):
        instance = gateway()
        ask(instance)
        assert "reasoning" not in instance.transport.requests[0]

    def test_the_answering_model_is_recorded_when_a_fallback_is_used(self):
        instance = gateway(
            (200, completion(model="b:free"), {}), model="a:free", fallback_models=("b:free",)
        )
        response = ask(instance)
        assert response.model == "b:free"
        assert response.usage["fallback_used"] is True
        assert instance.routed_models == {"b:free": 1}

    def test_running_out_of_tokens_while_reasoning_is_explained(self):
        body = {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}
        instance = gateway((200, body, {}))
        with pytest.raises(Exception, match="AEGIS_AI_MAX_TOKENS"):
            ask(instance)

    def test_the_factory_carries_roles_fallbacks_and_pacing(self, tmp_path):
        config = load_config(start=tmp_path, environ=KEY, role="interactive")
        built = build_gateway(config)
        assert isinstance(built, OpenRouterGateway)
        assert built.model_id == PROVIDER_DEFAULTS["openrouter"]["interactive_model"]
        assert built.fallback_models == PROVIDER_DEFAULTS["openrouter"]["fallback_models"]
        assert built.reasoning_effort == "low"
        assert built.min_interval == pytest.approx(60.0 / 16.0)


# --- rate limits ------------------------------------------------------------


class TestRateLimits:
    def test_requests_are_paced_before_they_trip_a_limit(self):
        now = [0.0]
        slept = []

        def sleep(seconds):
            slept.append(round(seconds, 6))
            now[0] += seconds

        instance = gateway(requests_per_minute=60, sleep=sleep, clock=lambda: now[0])
        for _ in range(3):
            ask(instance)
        assert slept == [1.0, 1.0]

    def test_a_daily_quota_fails_fast_without_retrying(self):
        tomorrow_ms = str(int((time.time() + 6 * 3600) * 1000))
        quota = (
            429,
            {"error": {"message": "Rate limit exceeded: free-models-per-day"}},
            {"X-RateLimit-Limit": "50", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": tomorrow_ms},
        )
        instance = gateway(quota, max_retries=3)
        with pytest.raises(QuotaExhausted, match="resets at") as caught:
            ask(instance)
        assert len(instance.transport.requests) == 1, "a quota must not be retried"
        assert caught.value.reset_at > time.time()

        # Every later call in the run fails without spending a request.
        with pytest.raises(QuotaExhausted):
            ask(instance)
        assert len(instance.transport.requests) == 1
        assert instance.available is False

    def test_a_short_rate_limit_is_waited_out_once(self):
        slept = []
        instance = gateway(
            (429, {"error": {"message": "slow down"}}, {"Retry-After": "2"}),
            sleep=slept.append,
        )
        assert ask(instance).data["exploitable"] is True
        assert slept == [2.0]
        assert instance.retries == 1

    def test_quota_exhaustion_leaves_every_finding_with_its_static_verdict(self, audit):
        tomorrow_ms = str(int((time.time() + 3600 * 5) * 1000))
        quota = (429, {"error": {"message": "daily"}}, {"X-RateLimit-Reset": tomorrow_ms})
        instance = gateway(quota)
        index = audit("cmd_injection.c")
        before = [(f.rule_id, f.path.fingerprint) for f in index.findings]
        adjudicator = Adjudicator(instance, max_workers=1)
        adjudicator.run(index)
        assert [(f.rule_id, f.path.fingerprint) for f in index.findings] == before
        assert adjudicator.stats.errors == len(index.findings)
        assert len(instance.transport.requests) == 1, "one request learned the quota; none after"
        assert any("quota exhausted" in failure for failure in adjudicator.stats.failures)

    def test_rate_limit_headers_are_recorded_from_successful_responses(self):
        instance = gateway(
            (200, completion(), {"x-ratelimit-limit": "50", "x-ratelimit-remaining": "41"})
        )
        ask(instance)
        assert instance.rate_limit["limit"] == "50"
        assert instance.rate_limit["remaining"] == "41"

    def test_reset_headers_normalise_to_epoch_seconds(self):
        now = 1_800_000_000.0
        assert reset_epoch({"X-RateLimit-Reset": "1800000123000"}, now) == pytest.approx(1_800_000_123)
        assert reset_epoch({"X-RateLimit-Reset": "1800000123"}, now) == pytest.approx(1_800_000_123)
        assert reset_epoch({"X-RateLimit-Reset": "30"}, now) == pytest.approx(now + 30)
        assert reset_epoch({"Retry-After": "5"}, now) == pytest.approx(now + 5)
        assert reset_epoch({}, now) is None

    def test_header_lookup_ignores_case(self):
        assert header({"X-RateLimit-Remaining": "3"}, "x-ratelimit-remaining") == "3"
        assert header({}, "anything") is None


# --- the IDE uses the interactive role --------------------------------------


class TestServerRole:
    def test_the_language_server_adjudicates_with_the_interactive_role(self, monkeypatch):
        from pathlib import Path

        import aegis.ai.config as config_module
        from aegis.server import lsp_server

        seen = {}

        def fake_load_config(*args, **kwargs):
            seen["role"] = kwargs.get("role", "review")
            return AIConfig()  # unconfigured: no request can be made

        monkeypatch.setattr(config_module, "load_config", fake_load_config)
        example = Path(__file__).resolve().parent.parent / "examples" / "cmd_injection.c"
        payload = lsp_server.adjudicate(lsp_server.server, example.as_uri())
        assert seen["role"] == "interactive"
        assert payload["adjudication"]["role"] == "interactive"
        assert payload["adjudication"]["reason"] == "no API key configured"


# --- upstream errors from a routing gateway ---------------------------------
#
# Every case here was observed live against OpenRouter free endpoints.


class TestUpstreamErrors:
    def test_an_overloaded_upstream_inside_a_200_is_retried(self):
        overloaded = (
            200,
            {"error": {"message": "Upstream error from Nvidia: Service temporarily overloaded"}},
            {},
        )
        slept = []
        instance = gateway(overloaded, sleep=slept.append)
        assert ask(instance).data["exploitable"] is True
        assert instance.retries == 1 and len(slept) == 1

    def test_the_error_type_field_classifies_without_reading_prose(self):
        body = {"error": {"message": "x", "metadata": {"error_type": "provider_overloaded"}}}
        instance = gateway((200, body, {}))
        assert ask(instance).data["exploitable"] is True
        assert instance.retries == 1

    def test_persistent_overload_is_reported_after_the_retry_budget(self):
        overloaded = (200, {"error": {"message": "Service temporarily overloaded"}}, {})
        instance = gateway(*[overloaded] * 5, max_retries=2)
        with pytest.raises(Exception, match="temporarily overloaded"):
            ask(instance)
        assert len(instance.transport.requests) == 3

    def test_the_error_names_every_model_in_the_fallback_chain(self):
        overloaded = (200, {"error": {"message": "Upstream error from Nvidia: overloaded"}}, {})
        instance = gateway(
            *[overloaded] * 5, model="a:free", fallback_models=("b:free", "c:free"), max_retries=0
        )
        with pytest.raises(Exception, match="models tried in order: a:free, b:free, c:free"):
            ask(instance)

    def test_the_real_upstream_reason_is_surfaced(self):
        # "Provider returned error" alone tells the user nothing.
        body = {
            "error": {
                "code": 429,
                "message": "Provider returned error",
                "metadata": {
                    "raw": "poolside/laguna-s-2.1:free is temporarily rate-limited upstream.",
                    "limit_source": "upstream_provider_shared_pool",
                },
            }
        }
        instance = gateway(*[(429, body, {})] * 5, max_retries=1)
        with pytest.raises(Exception, match="rate-limited upstream"):
            ask(instance)
        assert len(instance.transport.requests) == 2

    def test_the_agentic_harness_gate_is_explained_and_not_retried(self):
        gated = (
            403,
            {"error": {"code": 403, "message": "thinkingmachines/inkling:free is only available "
                                               "on agentic harnesses."}},
            {},
        )
        instance = gateway(gated, max_retries=3)
        with pytest.raises(Exception, match="another free model"):
            ask(instance)
        assert len(instance.transport.requests) == 1

    def test_a_data_policy_refusal_names_the_fix_and_is_not_retried(self):
        refused = (
            404,
            {"error": {"message": "No endpoints found matching your data policy (Free model training)"}},
            {},
        )
        instance = gateway(refused, max_retries=3)
        with pytest.raises(Exception, match="settings/privacy"):
            ask(instance)
        assert len(instance.transport.requests) == 1


# --- the cache distinguishes roles ------------------------------------------


class TestCacheVariants:
    def test_different_reasoning_effort_does_not_share_a_verdict(self, tmp_path):
        from aegis.ai.gateway.cache import CachingGateway

        review = CachingGateway(gateway(model="m:free", reasoning_effort="medium"), tmp_path)
        interactive = CachingGateway(gateway(model="m:free", reasoning_effort="low"), tmp_path)
        review.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        interactive.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        assert interactive.hits == 0, "a low-effort review must not reuse a medium-effort verdict"
        assert len(interactive.inner.transport.requests) == 1

    def test_the_same_role_is_still_served_from_cache(self, tmp_path):
        from aegis.ai.gateway.cache import CachingGateway

        first = CachingGateway(gateway(model="m:free", reasoning_effort="low"), tmp_path)
        second = CachingGateway(gateway(model="m:free", reasoning_effort="low"), tmp_path)
        first.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        second.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        assert second.hits == 1
        assert second.inner.transport.requests == []

    def test_entries_without_a_variant_keep_their_old_keys(self):
        from aegis.ai.gateway.cache import cache_key

        assert cache_key("m", "s", "u", None, 0.0) == cache_key("m", "s", "u", None, 0.0, "")
