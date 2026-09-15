"""Tests for the adjudication layer.

Every test here runs against a fake transport. A test suite that needs a
credential is a test suite that does not run in CI, and one that needs a
network is not deterministic -- so the gateway takes its transport as a
parameter and these tests supply it.

The tests worth reading first are in :class:`TestInvariants`. They are the
executable form of the project's central claim: adjudication may lower
confidence and dismiss a path, but it cannot create a finding, cannot raise a
confidence, and cannot change what the compiler reports when it fails.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.ai.adjudicator import Adjudicator, SYSTEM_PROMPT, VERDICT_SCHEMA, dismissed
from aegis.ai.config import AIConfig, load_config
from aegis.ai.gateway import build_gateway
from aegis.ai.gateway.anthropic import AnthropicGateway, GatewayError, _extract_verdict
from aegis.ai.gateway.cache import CachingGateway, cache_key
from aegis.ai.gateway.null import NullGateway


# --- helpers ----------------------------------------------------------------


def tool_use_body(exploitable=True, confidence=0.9, reason="because", control="", model="m"):
    """A Messages API response shaped as a forced tool call."""
    return {
        "id": "msg_1",
        "model": model,
        "stop_reason": "tool_use",
        "content": [
            {
                "type": "tool_use",
                "id": "tu_1",
                "name": "record_verdict",
                "input": {
                    "exploitable": exploitable,
                    "confidence": confidence,
                    "reason": reason,
                    "missing_control": control,
                },
            }
        ],
        "usage": {"input_tokens": 120, "output_tokens": 30},
    }


class FakeTransport:
    """Replays a queued script of ``(status, body)`` pairs and records requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, url, body, headers, timeout):
        self.requests.append(
            {
                "url": url,
                "payload": json.loads(body.decode()),
                "headers": headers,
                "timeout": timeout,
            }
        )
        status, payload = self.responses.pop(0) if self.responses else (200, tool_use_body())
        if isinstance(payload, Exception):
            raise payload
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, raw, {}


def gateway(*responses, **kwargs):
    transport = FakeTransport(*responses)
    instance = AnthropicGateway(
        api_key="test-key",
        model="test-model",
        transport=transport,
        sleep=lambda _seconds: None,  # no real backoff in tests
        **kwargs,
    )
    instance.transport = transport
    return instance


def ask(instance, user="CANDIDATE: CWE-78"):
    return instance.complete(system=SYSTEM_PROMPT, user=user, schema=VERDICT_SCHEMA)


# --- configuration ----------------------------------------------------------


class TestConfig:
    def test_absent_key_means_disabled_not_broken(self, tmp_path):
        config = load_config(start=tmp_path, environ={})
        assert config.configured is False
        assert config.enabled is False

    def test_aegis_key_wins_over_the_generic_one(self, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={"AEGIS_API_KEY": "a", "ANTHROPIC_API_KEY": "b"},
        )
        assert config.api_key == "a"
        assert config.sources["api_key"] == "AEGIS_API_KEY"

    def test_falls_back_to_the_generic_key(self, tmp_path):
        config = load_config(start=tmp_path, environ={"ANTHROPIC_API_KEY": "b"})
        assert config.api_key == "b"

    def test_describe_never_contains_the_key(self, tmp_path):
        config = load_config(start=tmp_path, environ={"AEGIS_API_KEY": "super-secret-value"})
        rendered = json.dumps(config.describe())
        assert "super-secret-value" not in rendered
        assert config.key_fingerprint != "-"
        assert len(config.key_fingerprint) == 12

    def test_a_key_in_a_config_file_is_refused(self, tmp_path):
        (tmp_path / "aegis.toml").write_text(
            '[tool.aegis.ai]\napi_key = "leaked"\nmodel = "from-file"\n', encoding="utf-8"
        )
        config = load_config(start=tmp_path, environ={})
        # The model is honoured; the credential is not, because the file is the
        # thing that gets committed.
        assert config.model == "from-file"
        assert config.api_key == ""
        assert "ignored" in config.sources["api_key"]

    def test_environment_overrides_the_file(self, tmp_path):
        (tmp_path / "aegis.toml").write_text(
            '[tool.aegis.ai]\nmodel = "from-file"\n', encoding="utf-8"
        )
        config = load_config(start=tmp_path, environ={"AEGIS_MODEL": "from-env"})
        assert config.model == "from-env"


# --- the live gateway -------------------------------------------------------


class TestAnthropicGateway:
    def test_forces_the_verdict_tool(self):
        instance = gateway((200, tool_use_body()))
        ask(instance)
        payload = instance.transport.requests[0]["payload"]
        assert payload["tool_choice"] == {"type": "tool", "name": "record_verdict"}
        assert payload["tools"][0]["input_schema"] == VERDICT_SCHEMA
        assert payload["temperature"] == 0.0

    def test_sends_credentials_in_headers_not_the_body(self):
        instance = gateway((200, tool_use_body()))
        ask(instance)
        request = instance.transport.requests[0]
        assert request["headers"]["x-api-key"] == "test-key"
        assert "test-key" not in json.dumps(request["payload"])

    def test_returns_the_structured_verdict(self):
        instance = gateway((200, tool_use_body(exploitable=False, confidence=0.25)))
        response = ask(instance)
        assert response.data["exploitable"] is False
        assert response.data["confidence"] == 0.25
        assert response.usage["input_tokens"] == 120
        assert response.cached is False

    def test_retries_a_rate_limit_then_succeeds(self):
        instance = gateway(
            (429, {"error": {"message": "slow down"}}),
            (200, tool_use_body()),
        )
        response = ask(instance)
        assert response.data["exploitable"] is True
        assert instance.retries == 1
        assert len(instance.transport.requests) == 2

    def test_retries_a_server_error(self):
        instance = gateway((503, {}), (500, {}), (200, tool_use_body()))
        assert ask(instance).data["confidence"] == 0.9
        assert instance.retries == 2

    def test_gives_up_after_the_retry_budget(self):
        instance = gateway(*[(503, {})] * 5, max_retries=2)
        with pytest.raises(GatewayError) as caught:
            ask(instance)
        assert caught.value.status == 503
        assert len(instance.transport.requests) == 3  # the first try plus two retries

    def test_a_bad_key_is_not_retried(self):
        # Retrying a rejected credential burns quota and cannot succeed.
        instance = gateway((401, {"error": {"message": "invalid x-api-key"}}))
        with pytest.raises(GatewayError) as caught:
            ask(instance)
        assert caught.value.status == 401
        assert caught.value.retryable is False
        assert "AEGIS_API_KEY" in str(caught.value)
        assert len(instance.transport.requests) == 1

    def test_an_unknown_model_reports_the_detail(self):
        instance = gateway((404, {"error": {"message": "model: nope"}}))
        with pytest.raises(GatewayError, match="model: nope"):
            ask(instance)

    def test_malformed_body_raises_rather_than_guessing(self):
        instance = gateway((200, b"not json at all"))
        with pytest.raises(GatewayError, match="malformed response"):
            ask(instance)

    def test_a_response_without_a_verdict_raises(self):
        instance = gateway((200, {"content": [], "stop_reason": "end_turn"}))
        with pytest.raises(GatewayError, match="no structured verdict"):
            ask(instance)

    def test_transport_failure_is_retried_then_surfaced(self):
        boom = GatewayError("cannot reach the model endpoint", retryable=True)
        instance = gateway((0, boom), (0, boom), (0, boom), (0, boom), max_retries=2)
        with pytest.raises(GatewayError, match="cannot reach"):
            ask(instance)

    def test_budget_is_enforced(self):
        instance = gateway(*[(200, tool_use_body())] * 5, max_requests=2)
        ask(instance)
        ask(instance)
        with pytest.raises(GatewayError, match="budget exhausted"):
            ask(instance)

    def test_retry_after_header_is_honoured(self):
        delays = []
        transport = FakeTransport((429, {}), (200, tool_use_body()))

        def timed(url, body, headers, timeout):
            status, raw, _ = transport(url, body, headers, timeout)
            return status, raw, {"retry-after": "7"}

        instance = AnthropicGateway(
            api_key="k", transport=timed, sleep=delays.append, max_retries=2
        )
        ask(instance)
        assert delays == [7.0]

    def test_no_key_is_refused_at_construction(self):
        with pytest.raises(GatewayError, match="no API key"):
            AnthropicGateway(api_key="")

    def test_text_json_is_accepted_when_no_schema_was_forced(self):
        body = {
            "content": [{"type": "text", "text": '```json\n{"exploitable": false}\n```'}],
            "model": "m",
        }
        assert _extract_verdict(body, expect_tool=False)["exploitable"] is False


# --- the cache --------------------------------------------------------------


class TestCache:
    def test_identical_input_is_served_from_disk(self, tmp_path):
        inner = gateway((200, tool_use_body()))
        cached = CachingGateway(inner, tmp_path)
        first = cached.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        second = cached.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        assert first.data == second.data
        assert second.cached is True
        assert len(inner.transport.requests) == 1  # the second never left the machine
        assert cached.stats() == {"hits": 1, "misses": 1, "writes": 1, "hit_rate": 0.5}

    def test_changed_source_misses(self, tmp_path):
        inner = gateway((200, tool_use_body()), (200, tool_use_body(confidence=0.1)))
        cached = CachingGateway(inner, tmp_path)
        cached.complete("sys", "path A", VERDICT_SCHEMA, 0.0)
        second = cached.complete("sys", "path B", VERDICT_SCHEMA, 0.0)
        assert second.data["confidence"] == 0.1
        assert len(inner.transport.requests) == 2

    def test_key_covers_every_input(self):
        base = cache_key("m", "s", "u", VERDICT_SCHEMA, 0.0)
        assert base != cache_key("other", "s", "u", VERDICT_SCHEMA, 0.0)
        assert base != cache_key("m", "s2", "u", VERDICT_SCHEMA, 0.0)
        assert base != cache_key("m", "s", "u2", VERDICT_SCHEMA, 0.0)
        assert base != cache_key("m", "s", "u", None, 0.0)
        assert base != cache_key("m", "s", "u", VERDICT_SCHEMA, 1.0)

    def test_a_corrupt_entry_is_a_miss_not_a_crash(self, tmp_path):
        inner = gateway((200, tool_use_body()), (200, tool_use_body()))
        cached = CachingGateway(inner, tmp_path)
        cached.complete("sys", "user", VERDICT_SCHEMA, 0.0)
        for path in tmp_path.rglob("*.json"):
            path.write_text("{ truncated", encoding="utf-8")
        assert cached.complete("sys", "user", VERDICT_SCHEMA, 0.0).data["exploitable"] is True

    def test_an_unwritable_directory_does_not_fail_the_audit(self, tmp_path):
        blocker = tmp_path / "blocked"
        blocker.write_text("i am a file, not a directory", encoding="utf-8")
        cached = CachingGateway(gateway((200, tool_use_body())), blocker)
        assert cached.complete("sys", "user", VERDICT_SCHEMA, 0.0).data["exploitable"] is True


# --- gateway selection ------------------------------------------------------


class TestFactory:
    def test_no_key_yields_the_deterministic_gateway(self):
        assert isinstance(build_gateway(AIConfig()), NullGateway)

    def test_a_key_yields_a_live_gateway(self):
        built = build_gateway(AIConfig(api_key="k", cache_enabled=False))
        assert isinstance(built, AnthropicGateway)
        assert built.model_id == AIConfig().model

    def test_caching_is_wrapped_around_the_live_gateway(self, tmp_path):
        built = build_gateway(AIConfig(api_key="k", cache_enabled=True, cache_dir=tmp_path))
        assert isinstance(built, CachingGateway)
        assert isinstance(built.inner, AnthropicGateway)

    def test_an_unknown_provider_degrades_rather_than_raising(self):
        assert isinstance(build_gateway(AIConfig(api_key="k", provider="mystery")), NullGateway)


# --- the invariants ---------------------------------------------------------


class TestInvariants:
    """The claims the project makes about adjudication, as executable checks."""

    def test_adjudication_cannot_create_a_finding(self, audit):
        index = audit("cmd_injection.c")
        before = len(index.findings)
        # A response insisting on extra findings changes nothing: the pass
        # iterates an existing list.
        instance = gateway(*[(200, tool_use_body())] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert len(index.findings) == before

    def test_confidence_can_fall(self, audit):
        index = audit("cmd_injection.c")
        for finding in index.findings:
            finding.path.confidence = 1.0
        instance = gateway(*[(200, tool_use_body(confidence=0.2))] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert all(f.path.confidence == 0.2 for f in index.findings)

    def test_confidence_cannot_rise(self, audit):
        index = audit("cmd_injection.c")
        for finding in index.findings:
            finding.path.confidence = 0.4
        instance = gateway(*[(200, tool_use_body(confidence=0.99))] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert all(f.path.confidence == 0.4 for f in index.findings)

    def test_out_of_range_confidence_is_clamped(self, audit):
        index = audit("cmd_injection.c")
        instance = gateway(*[(200, tool_use_body(confidence=7.5))] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert all(0.0 <= f.confidence <= 1.0 for f in index.findings)

    def test_nonsense_confidence_falls_back(self, audit):
        index = audit("cmd_injection.c")
        instance = gateway(*[(200, tool_use_body(confidence="banana"))] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert all(0.0 <= f.confidence <= 1.0 for f in index.findings)

    def test_severity_is_never_touched(self, audit):
        index = audit("cmd_injection.c")
        before = [f.severity for f in index.findings]
        instance = gateway(*[(200, tool_use_body(exploitable=False))] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert [f.severity for f in index.findings] == before

    def test_a_gateway_failure_keeps_the_static_verdict(self, audit):
        index = audit("cmd_injection.c")
        before = [(f.rule_id, f.path.fingerprint, f.severity) for f in index.findings]
        instance = gateway(*[(401, {"error": {"message": "nope"}})] * 20)
        adjudicator = Adjudicator(instance, max_workers=1)
        adjudicator.run(index)
        assert [(f.rule_id, f.path.fingerprint, f.severity) for f in index.findings] == before
        assert adjudicator.stats.errors == len(index.findings)
        assert all(f.adjudicator == "unavailable" for f in index.findings)
        assert all(f.exploitable is None for f in index.findings)

    def test_absolute_paths_are_redacted_from_prompts(self, audit):
        index = audit("cmd_injection.c")
        # The directory this test actually runs from, whatever that is.
        enclosing = Path(index.findings[0].path.sink.file).parent.name
        instance = gateway(*[(200, tool_use_body())] * 20)
        Adjudicator(instance, max_workers=1, redact_paths=True).run(index)
        sent = json.dumps(instance.transport.requests)

        assert "cmd_injection.c" in sent, "the file being reviewed must still be named"
        assert enclosing not in sent, "the directory it sits in must not be"

    def test_redaction_can_be_turned_off(self, audit):
        index = audit("cmd_injection.c")
        enclosing = Path(index.findings[0].path.sink.file).parent.name
        instance = gateway(*[(200, tool_use_body())] * 20)
        Adjudicator(instance, max_workers=1, redact_paths=False).run(index)
        assert enclosing in json.dumps(instance.transport.requests)


class TestAdjudicatorBehaviour:
    def test_dismissal_is_recorded_not_deleted(self, audit):
        index = audit("cmd_injection.c")
        instance = gateway(*[(200, tool_use_body(exploitable=False, reason="guarded"))] * 20)
        adjudicator = Adjudicator(instance, max_workers=1)
        adjudicator.run(index)
        assert adjudicator.stats.dismissed == len(index.findings)
        assert len(dismissed(index.findings)) == len(index.findings)
        assert index.findings, "dismissed findings stay in the index for review"
        assert all(f.reason == "guarded" for f in index.findings)

    def test_missing_control_fills_a_gap_but_never_overwrites(self, audit):
        index = audit("cmd_injection.c")
        index.findings[0].missing_control = "detector wording"
        index.findings[-1].missing_control = ""
        instance = gateway(*[(200, tool_use_body(control="model wording"))] * 20)
        Adjudicator(instance, max_workers=1).run(index)
        assert index.findings[0].missing_control == "detector wording"
        assert index.findings[-1].missing_control == "model wording"

    def test_stats_are_reportable(self, audit):
        index = audit("cmd_injection.c")
        instance = gateway(*[(200, tool_use_body())] * 20)
        adjudicator = Adjudicator(instance, max_workers=1)
        adjudicator.run(index)
        stats = adjudicator.stats.as_dict()
        assert stats["candidates"] == len(index.findings)
        assert stats["adjudicated"] == len(index.findings)
        assert stats["input_tokens"] > 0
        assert 0.0 < stats["mean_context_reduction"] < 1.0
        assert stats["model"] == "test-model"

    def test_enabled_sees_through_the_cache_wrapper(self, tmp_path):
        assert Adjudicator(NullGateway()).enabled is False
        assert Adjudicator(CachingGateway(NullGateway(), tmp_path)).enabled is False
        assert Adjudicator(gateway()).enabled is True

    def test_an_empty_index_costs_nothing(self, audit):
        index = audit("safe.c")
        instance = gateway()
        Adjudicator(instance, max_workers=1).run(index)
        assert instance.transport.requests == []

    def test_concurrent_adjudication_preserves_order(self, audit):
        index = audit("cmd_injection.c")
        order = [f.path.fingerprint for f in index.findings]
        instance = gateway(*[(200, tool_use_body())] * 40)
        Adjudicator(instance, max_workers=4).run(index)
        assert [f.path.fingerprint for f in index.findings] == order

    def test_demotion_count_matches_what_a_reader_would_count(self, audit):
        """`demoted` must agree with the report-level gate.

        The static analysis states no confidence, which the reporting layer
        shows as 1.0. A verdict of 0.9 is therefore a demotion, and counting it
        any other way makes the CLI and `eval/check_invariants.py` disagree
        about the same run.
        """
        index = audit("cmd_injection.c")
        assert all(f.path.confidence is None for f in index.findings)
        instance = gateway(*[(200, tool_use_body(confidence=0.9))] * 20)
        adjudicator = Adjudicator(instance, max_workers=1)
        adjudicator.run(index)
        assert adjudicator.stats.demoted == len(index.findings)

    def test_a_verdict_of_full_confidence_is_not_a_demotion(self, audit):
        index = audit("cmd_injection.c")
        instance = gateway(*[(200, tool_use_body(confidence=1.0))] * 20)
        adjudicator = Adjudicator(instance, max_workers=1)
        adjudicator.run(index)
        assert adjudicator.stats.demoted == 0
