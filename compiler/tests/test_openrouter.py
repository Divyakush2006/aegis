"""OpenRouter: the gateway, the configuration that selects it, and the catalogue.

Every test here is hermetic. The gateway tests inject a transport, the
catalogue tests inject an opener, and the end-to-end tests talk to
``eval/mock_model.py`` on a loopback port -- so none of them needs a key, and
none of them can spend one.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from aegis.ai.adjudicator import SYSTEM_PROMPT, VERDICT_SCHEMA, Adjudicator
from aegis.ai.catalogue import ModelInfo, fetch_models, rank_for_adjudication
from aegis.ai.config import load_config, read_env_file
from aegis.ai.gateway import build_gateway
from aegis.ai.gateway.anthropic import AnthropicGateway
from aegis.ai.gateway.cache import CachingGateway
from aegis.ai.gateway.http import GatewayError
from aegis.ai.gateway.openrouter import DEFAULT_BASE_URL, DEFAULT_MODEL, OpenRouterGateway

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))
from mock_model import Handler, serve  # noqa: E402

VERDICT = {
    "exploitable": True,
    "confidence": 0.7,
    "reason": "no guard constrains the value",
    "missing_control": "input validation",
}


def completion(verdict=VERDICT, *, as_tool=True, arguments=None, model=DEFAULT_MODEL):
    """An OpenAI-shaped chat completion, as OpenRouter returns it."""
    if as_tool:
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "record_verdict",
                        "arguments": json.dumps(verdict) if arguments is None else arguments,
                    },
                }
            ],
        }
    else:
        message = {"role": "assistant", "content": json.dumps(verdict)}
    return {
        "id": "gen-1",
        "model": model,
        "choices": [
            {"index": 0, "message": message, "finish_reason": "tool_calls" if as_tool else "stop"}
        ],
        "usage": {"prompt_tokens": 210, "completion_tokens": 40, "total_tokens": 250},
    }


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, url, body, headers, timeout):
        self.requests.append({"url": url, "payload": json.loads(body), "headers": headers})
        status, payload = self.responses.pop(0) if self.responses else (200, completion())
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, raw, {}


def gateway(*responses, **kwargs):
    transport = Transport(*responses)
    instance = OpenRouterGateway(
        api_key="sk-or-v1-test", transport=transport, sleep=lambda _s: None, **kwargs
    )
    instance.transport = transport
    return instance


def ask(instance):
    return instance.complete(system=SYSTEM_PROMPT, user="CANDIDATE: CWE-78", schema=VERDICT_SCHEMA)


# --- the request ------------------------------------------------------------


class TestRequest:
    def test_posts_to_chat_completions(self):
        instance = gateway()
        ask(instance)
        assert instance.transport.requests[0]["url"] == f"{DEFAULT_BASE_URL}/chat/completions"

    def test_authenticates_with_a_bearer_token_in_headers_only(self):
        instance = gateway()
        ask(instance)
        request = instance.transport.requests[0]
        assert request["headers"]["authorization"] == "Bearer sk-or-v1-test"
        assert "sk-or-v1-test" not in json.dumps(request["payload"])

    def test_attribution_headers_carry_no_secret(self):
        instance = gateway()
        ask(instance)
        headers = instance.transport.requests[0]["headers"]
        assert headers["x-title"] and headers["http-referer"]
        assert "sk-or" not in headers["x-title"] + headers["http-referer"]

    def test_system_prompt_is_a_message(self):
        instance = gateway()
        ask(instance)
        messages = instance.transport.requests[0]["payload"]["messages"]
        assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
        assert messages[1]["role"] == "user"

    def test_forces_the_verdict_function(self):
        instance = gateway()
        ask(instance)
        payload = instance.transport.requests[0]["payload"]
        assert payload["tools"][0]["type"] == "function"
        assert payload["tools"][0]["function"]["parameters"] == VERDICT_SCHEMA
        assert payload["tool_choice"] == {
            "type": "function",
            "function": {"name": "record_verdict"},
        }
        assert payload["temperature"] == 0.0
        assert payload["model"] == DEFAULT_MODEL


# --- the response -----------------------------------------------------------


class TestResponse:
    def test_arguments_arrive_as_a_string_and_are_parsed(self):
        response = ask(gateway((200, completion())))
        assert response.data == VERDICT
        assert response.usage["used_tool_call"] is True

    def test_pre_decoded_arguments_are_accepted(self):
        response = ask(gateway((200, completion(arguments=VERDICT))))
        assert response.data == VERDICT

    def test_invalid_argument_json_raises(self):
        with pytest.raises(GatewayError, match="not valid JSON"):
            ask(gateway((200, completion(arguments="{not json"))))

    def test_a_model_without_tool_support_still_yields_a_verdict(self):
        instance = gateway((200, completion(as_tool=False)))
        response = ask(instance)
        assert response.data == VERDICT
        assert instance.used_tool_call is False
        assert response.usage["used_tool_call"] is False

    def test_require_tools_rejects_a_prose_answer(self):
        with pytest.raises(GatewayError, match="did not call the verdict tool"):
            ask(gateway((200, completion(as_tool=False)), require_tools=True))

    def test_content_blocks_are_accepted(self):
        body = completion(as_tool=False)
        body["choices"][0]["message"]["content"] = [
            {"type": "text", "text": json.dumps(VERDICT)}
        ]
        assert ask(gateway((200, body))).data == VERDICT

    def test_no_choices_raises(self):
        with pytest.raises(GatewayError, match="no choices"):
            ask(gateway((200, {"id": "gen-x", "choices": []})))

    def test_a_transient_error_inside_a_200_body_is_retried(self):
        # OpenRouter reports some upstream failures with status 200; a 502 code
        # inside the body is as transient as a 502 status.
        body = {"error": {"message": "upstream provider unavailable", "code": 502}}
        instance = gateway((200, body), (200, completion()))
        assert ask(instance).data == VERDICT
        assert instance.retries == 1

    def test_a_permanent_error_inside_a_200_body_raises(self):
        body = {"error": {"message": "invalid request shape", "code": 400}}
        instance = gateway((200, body))
        with pytest.raises(GatewayError, match="invalid request shape"):
            ask(instance)
        assert len(instance.transport.requests) == 1

    def test_usage_is_normalised_to_the_shared_names(self):
        instance = gateway((200, completion()))
        response = ask(instance)
        assert response.usage["input_tokens"] == 210
        assert response.usage["output_tokens"] == 40
        assert (instance.input_tokens, instance.output_tokens) == (210, 40)

    def test_records_the_routed_model(self):
        response = ask(gateway((200, completion(model="openai/gpt-4o"))))
        assert response.model == "openai/gpt-4o"


class TestErrors:
    def test_no_credit_is_reported_plainly_and_not_retried(self):
        instance = gateway((402, {"error": {"message": "Insufficient credits"}}))
        with pytest.raises(GatewayError, match="no credit") as caught:
            ask(instance)
        assert caught.value.retryable is False
        assert len(instance.transport.requests) == 1

    def test_rate_limit_is_retried(self):
        instance = gateway((429, {"error": {"message": "slow"}}), (200, completion()))
        assert ask(instance).data == VERDICT
        assert instance.retries == 1

    def test_rejected_key_is_not_retried(self):
        instance = gateway((401, {"error": {"message": "No auth credentials found"}}))
        with pytest.raises(GatewayError, match="rejected"):
            ask(instance)
        assert len(instance.transport.requests) == 1


# --- selecting the provider -------------------------------------------------


class TestProviderSelection:
    def test_an_openrouter_key_selects_openrouter(self, tmp_path):
        config = load_config(start=tmp_path, environ={"AEGIS_API_KEY": "sk-or-v1-abc"})
        assert config.provider == "openrouter"
        assert config.base_url == DEFAULT_BASE_URL
        assert config.model == DEFAULT_MODEL
        assert config.sources["provider"] == "detected from the key prefix"

    def test_the_openrouter_variable_implies_the_provider(self, tmp_path):
        config = load_config(start=tmp_path, environ={"OPENROUTER_API_KEY": "unprefixed-key"})
        assert config.provider == "openrouter"
        assert "OPENROUTER_API_KEY" in config.sources["provider"]

    def test_an_anthropic_key_selects_anthropic(self, tmp_path):
        config = load_config(start=tmp_path, environ={"AEGIS_API_KEY": "sk-ant-xyz"})
        assert config.provider == "anthropic"
        assert config.base_url == "https://api.anthropic.com"

    def test_an_explicit_provider_wins_over_detection(self, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={"AEGIS_API_KEY": "sk-or-v1-abc", "AEGIS_AI_PROVIDER": "anthropic"},
        )
        assert config.provider == "anthropic"

    def test_an_explicit_model_is_kept(self, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={"OPENROUTER_API_KEY": "sk-or-v1-abc", "AEGIS_MODEL": "openai/gpt-4o"},
        )
        assert config.model == "openai/gpt-4o"

    def test_the_factory_builds_the_openrouter_gateway(self, tmp_path):
        config = load_config(start=tmp_path, environ={"OPENROUTER_API_KEY": "sk-or-v1-abc"})
        config.cache_enabled = False
        built = build_gateway(config)
        assert isinstance(built, OpenRouterGateway)
        assert built.model_id == DEFAULT_MODEL

    def test_the_cache_wraps_it(self, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={"OPENROUTER_API_KEY": "sk-or-v1-abc", "AEGIS_AI_CACHE_DIR": str(tmp_path)},
        )
        built = build_gateway(config)
        assert isinstance(built, CachingGateway)
        assert isinstance(built.inner, OpenRouterGateway)
        assert Adjudicator(built).enabled is True

    def test_anthropic_still_builds(self, tmp_path):
        config = load_config(start=tmp_path, environ={"AEGIS_API_KEY": "sk-ant-xyz"})
        config.cache_enabled = False
        assert isinstance(build_gateway(config), AnthropicGateway)


# --- the .env file ----------------------------------------------------------


class TestEnvFile:
    def test_a_key_in_the_project_root_is_found_from_a_subdirectory(self, tmp_path):
        (tmp_path / ".env").write_text("OPENROUTER_API_KEY=sk-or-v1-from-file\n", encoding="utf-8")
        nested = tmp_path / "compiler" / "src"
        nested.mkdir(parents=True)
        config = load_config(start=nested, environ={})
        assert config.api_key == "sk-or-v1-from-file"
        assert config.provider == "openrouter"
        assert config.sources["api_key"] == str(tmp_path / ".env")

    def test_the_real_environment_overrides_the_file(self, tmp_path):
        (tmp_path / ".env").write_text("OPENROUTER_API_KEY=sk-or-v1-file\n", encoding="utf-8")
        config = load_config(start=tmp_path, environ={"OPENROUTER_API_KEY": "sk-or-v1-env"})
        assert config.api_key == "sk-or-v1-env"
        assert config.sources["api_key"] == "OPENROUTER_API_KEY"

    def test_the_file_can_be_switched_off(self, tmp_path):
        (tmp_path / ".env").write_text("OPENROUTER_API_KEY=sk-or-v1-file\n", encoding="utf-8")
        config = load_config(start=tmp_path, environ={"AEGIS_NO_DOTENV": "1"})
        assert config.configured is False

    def test_the_suite_itself_never_reads_a_developer_dotenv(self):
        import os

        assert os.environ.get("AEGIS_NO_DOTENV") == "1"
        assert not os.environ.get("OPENROUTER_API_KEY")

    def test_settings_other_than_the_key_come_from_the_file_too(self, tmp_path):
        (tmp_path / ".env").write_text(
            "OPENROUTER_API_KEY=sk-or-v1-x\nAEGIS_MODEL=google/gemini-2.5-pro\n"
            "AEGIS_AI_MAX_REQUESTS=12\n",
            encoding="utf-8",
        )
        config = load_config(start=tmp_path, environ={})
        assert config.model == "google/gemini-2.5-pro"
        assert config.max_requests == 12

    def test_describe_never_contains_a_key_read_from_the_file(self, tmp_path):
        (tmp_path / ".env").write_text("OPENROUTER_API_KEY=sk-or-v1-secret-9f\n", encoding="utf-8")
        config = load_config(start=tmp_path, environ={})
        assert "sk-or-v1-secret-9f" not in json.dumps(config.describe())

    def test_parser_handles_the_forms_people_actually_write(self, tmp_path):
        path = tmp_path / ".env"
        path.write_text(
            "# a comment\n"
            'export OPENROUTER_API_KEY="sk-or-v1-quoted"\n'
            "AEGIS_MODEL=openai/gpt-4o   # trailing comment\n"
            "SINGLE='single quoted'\n"
            "EMPTY=\n"
            "NOT A VALID LINE\n"
            "=no-name\n"
            "\n",
            encoding="utf-8",
        )
        values = read_env_file(path)
        assert values["OPENROUTER_API_KEY"] == "sk-or-v1-quoted"
        assert values["AEGIS_MODEL"] == "openai/gpt-4o"
        assert values["SINGLE"] == "single quoted"
        assert values["EMPTY"] == ""
        assert "" not in values
        assert not any(" " in name for name in values)

    def test_an_unreadable_file_is_ignored(self, tmp_path):
        assert read_env_file(tmp_path / "missing.env") == {}


# --- the catalogue ----------------------------------------------------------


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def opener_for(payload):
    seen = {}

    def opener(request, timeout):
        seen["url"] = request.full_url
        seen["authorization"] = request.get_header("Authorization")
        return _Response(json.dumps(payload).encode())

    return opener, seen


CATALOGUE = {
    "data": [
        {
            "id": "vendor/expensive-tools",
            "name": "Expensive",
            "context_length": 200000,
            "pricing": {"prompt": "0.000015", "completion": "0.000075"},
            "supported_parameters": ["tools", "tool_choice", "temperature"],
        },
        {
            "id": "vendor/cheap-tools",
            "name": "Cheap",
            "context_length": 128000,
            "pricing": {"prompt": "0.0000003", "completion": "0.0000012"},
            "supported_parameters": ["tools"],
        },
        {
            "id": "vendor/cheap-no-tools",
            "pricing": {"prompt": "0.0000001", "completion": "0.0000001"},
            "supported_parameters": ["temperature"],
        },
        {
            "id": "vendor/free-unpriced",
            "pricing": {"prompt": "0", "completion": "0"},
            "supported_parameters": ["tools"],
        },
    ]
}


class TestCatalogue:
    def test_fetches_the_models_endpoint_with_the_key(self):
        opener, seen = opener_for(CATALOGUE)
        models = fetch_models(DEFAULT_BASE_URL, "sk-or-v1-k", opener=opener)
        assert seen["url"] == f"{DEFAULT_BASE_URL}/models"
        assert seen["authorization"] == "Bearer sk-or-v1-k"
        assert len(models) == 4

    def test_parses_prices_and_tool_support(self):
        opener, _ = opener_for(CATALOGUE)
        by_id = {m.id: m for m in fetch_models(DEFAULT_BASE_URL, opener=opener)}
        assert by_id["vendor/expensive-tools"].supports_tools is True
        assert by_id["vendor/cheap-no-tools"].supports_tools is False
        assert by_id["vendor/cheap-tools"].prompt_price == pytest.approx(3e-7)
        assert by_id["vendor/expensive-tools"].context_length == 200000

    def test_ranking_puts_tool_support_before_price(self):
        opener, _ = opener_for(CATALOGUE)
        ranked = [m.id for m in rank_for_adjudication(fetch_models(DEFAULT_BASE_URL, opener=opener))]
        # Unpriced entries are excluded: a price of zero is usually "unknown",
        # and ranking on an unknown would put it first for the wrong reason.
        assert ranked == ["vendor/cheap-tools", "vendor/expensive-tools", "vendor/cheap-no-tools"]

    def test_blended_price_weights_input_heavily(self):
        info = ModelInfo(id="m", prompt_price=1e-6, completion_price=11e-6)
        # (1*10 + 11) / 11 = 1.909... USD per million
        assert info.price_per_million == pytest.approx(21 / 11)
        assert info.cost_for(1000, 100) == pytest.approx(1000e-6 + 1100e-6)

    def test_a_provider_without_a_catalogue_says_so(self):
        with pytest.raises(ValueError, match="no catalogue"):
            fetch_models("https://api.anthropic.com", provider="anthropic")

    def test_a_negative_price_means_unpublished(self):
        opener, _ = opener_for(
            {"data": [{"id": "x", "pricing": {"prompt": "-1", "completion": "-1"}}]}
        )
        assert fetch_models(DEFAULT_BASE_URL, opener=opener)[0].prompt_price == 0.0


# --- end to end over real HTTP ----------------------------------------------


@pytest.fixture
def openrouter_endpoint():
    server = serve(port=0)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def prose_endpoint():
    server = serve(port=0, no_tool_calls=True)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    Handler.no_tool_calls = False


def openrouter_config(endpoint, tmp_path):
    return load_config(
        start=tmp_path,
        environ={
            "OPENROUTER_API_KEY": "sk-or-v1-mock",
            "AEGIS_API_BASE": endpoint,
            "AEGIS_AI_CACHE": "0",
            "AEGIS_AI_RETRIES": "0",
        },
    )


class TestOverHttp:
    def test_the_whole_openrouter_path(self, audit, openrouter_endpoint, tmp_path):
        config = openrouter_config(openrouter_endpoint, tmp_path)
        assert config.provider == "openrouter"

        index = audit("cmd_injection.c")
        adjudicator = Adjudicator(build_gateway(config), max_workers=2)
        adjudicator.run(index)

        assert adjudicator.stats.errors == 0, adjudicator.stats.failures
        assert adjudicator.stats.adjudicated == len(index.findings)
        assert adjudicator.stats.input_tokens > 0
        assert Handler.requests_served == len(index.findings)
        assert all(f.adjudicator == DEFAULT_MODEL for f in index.findings)

    def test_a_model_that_answers_in_prose_still_works(self, audit, prose_endpoint, tmp_path):
        config = openrouter_config(prose_endpoint, tmp_path)
        index = audit("cmd_injection.c")
        adjudicator = Adjudicator(build_gateway(config), max_workers=1)
        adjudicator.run(index)
        assert adjudicator.stats.errors == 0, adjudicator.stats.failures
        assert all(f.reason for f in index.findings)

    def test_require_tools_turns_prose_into_contained_errors(self, audit, prose_endpoint, tmp_path):
        config = openrouter_config(prose_endpoint, tmp_path)
        config.require_tools = True
        index = audit("cmd_injection.c")
        before = len(index.findings)
        adjudicator = Adjudicator(build_gateway(config), max_workers=1)
        adjudicator.run(index)
        assert adjudicator.stats.errors == before
        assert len(index.findings) == before  # the compiler's findings survive
