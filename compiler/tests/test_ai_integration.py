"""End-to-end tests of the live adjudication path over real HTTP.

The tests in ``test_ai.py`` inject a transport, so they prove the gateway's
logic but never open a socket. These run against ``eval/mock_model.py`` on a
loopback port, which means the bytes actually travel through
``urllib_transport``: configuration resolution, header construction, the POST,
status handling, tool-use parsing and the clamping in the adjudicator are all
exercised as one path.

That distinction matters because the parts most likely to break in deployment
-- a header the endpoint rejects, a response shape that does not match -- are
exactly the parts a fake transport cannot catch.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from prahari.ai.adjudicator import Adjudicator
from prahari.ai.config import load_config
from prahari.ai.gateway import build_gateway
from prahari.ai.gateway.anthropic import AnthropicGateway, GatewayError
from prahari.ai.gateway.cache import CachingGateway

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))
from mock_model import Handler, serve  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "cmd_injection.c"


@pytest.fixture
def endpoint():
    """A mock model endpoint on an ephemeral port."""
    server = serve(port=0)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def failing_endpoint():
    server = serve(port=0, failure_mode="server_error")
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    Handler.failure_mode = None


def env_for(endpoint: str, cache: Path) -> dict:
    return {
        "PRAHARI_API_KEY": "mock-key",
        "PRAHARI_API_BASE": endpoint,
        "PRAHARI_AI_CACHE_DIR": str(cache),
        "PRAHARI_AI_RETRIES": "1",
    }


class TestLivePath:
    def test_the_whole_stack_over_real_http(self, audit, endpoint, tmp_path):
        config = load_config(start=tmp_path, environ=env_for(endpoint, tmp_path / "cache"))
        assert config.enabled is True

        index = audit("cmd_injection.c")
        adjudicator = Adjudicator(build_gateway(config), max_workers=2)
        assert adjudicator.enabled is True
        adjudicator.run(index)

        assert adjudicator.stats.errors == 0
        assert adjudicator.stats.adjudicated == len(index.findings)
        assert adjudicator.stats.input_tokens > 0
        assert all(f.adjudicator != "unavailable" for f in index.findings)
        assert all(f.reason for f in index.findings)
        assert all(0.0 <= f.confidence <= 1.0 for f in index.findings)

    def test_the_cache_survives_a_second_process_lifetime(self, audit, endpoint, tmp_path):
        cache = tmp_path / "cache"
        config = load_config(start=tmp_path, environ=env_for(endpoint, cache))

        first = build_gateway(config)
        Adjudicator(first, max_workers=1).run(audit("cmd_injection.c"))
        served = Handler.requests_served
        assert served > 0

        # A fresh gateway object, the same on-disk cache: nothing should reach
        # the endpoint the second time.
        second = build_gateway(config)
        assert isinstance(second, CachingGateway)
        Adjudicator(second, max_workers=1).run(audit("cmd_injection.c"))
        assert Handler.requests_served == served
        assert second.hits > 0

    def test_a_missing_key_is_rejected_by_the_endpoint(self, endpoint, tmp_path):
        gateway = AnthropicGateway(api_key="k", base_url=endpoint, max_retries=0)
        gateway.headers = lambda: {"content-type": "application/json"}  # drop the key
        with pytest.raises(GatewayError) as caught:
            gateway.complete(system="s", user="u", schema={"type": "object"})
        assert caught.value.status == 401

    def test_an_unreachable_endpoint_degrades_to_static_verdicts(self, audit, tmp_path):
        # Port 1 on loopback: nothing listens, so the connection is refused
        # rather than hanging.
        config = load_config(
            start=tmp_path,
            environ={
                "PRAHARI_API_KEY": "mock-key",
                "PRAHARI_API_BASE": "http://127.0.0.1:1",
                "PRAHARI_AI_RETRIES": "0",
                "PRAHARI_AI_TIMEOUT": "2",
            },
        )
        index = audit("cmd_injection.c")
        before = [(f.rule_id, f.severity, f.path.fingerprint) for f in index.findings]

        adjudicator = Adjudicator(build_gateway(config, use_cache=False), max_workers=1)
        adjudicator.run(index)

        assert adjudicator.stats.errors == len(index.findings)
        assert [(f.rule_id, f.severity, f.path.fingerprint) for f in index.findings] == before
        assert all(f.adjudicator == "unavailable" for f in index.findings)

    def test_server_errors_are_retried_then_contained(self, audit, failing_endpoint, tmp_path):
        config = load_config(
            start=tmp_path,
            environ={
                "PRAHARI_API_KEY": "mock-key",
                "PRAHARI_API_BASE": failing_endpoint,
                "PRAHARI_AI_RETRIES": "1",
            },
        )
        index = audit("cmd_injection.c")
        adjudicator = Adjudicator(build_gateway(config, use_cache=False), max_workers=1)
        adjudicator.run(index)
        assert adjudicator.stats.errors == len(index.findings)
        assert adjudicator.stats.adjudicated == 0
        assert index.findings, "findings survive a failed review"


class TestCommandLine:
    """The path a user actually takes, run as a subprocess."""

    def run(self, *args, env_extra=None):
        import os

        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["PYTHONIOENCODING"] = "utf-8"
        for key in ("PRAHARI_API_KEY", "ANTHROPIC_API_KEY", "PRAHARI_API_BASE"):
            env.pop(key, None)
        env.update(env_extra or {})
        return subprocess.run(
            [sys.executable, "-m", "prahari.cli", *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(ROOT),
            timeout=180,
        )

    def test_audit_adjudicates_over_http(self, endpoint, tmp_path):
        result = self.run(
            "audit", str(EXAMPLE), "--adjudicate", "--format", "json",
            env_extra=env_for(endpoint, tmp_path / "cache"),
        )
        assert result.returncode == 1, result.stderr  # findings present
        payload = json.loads(result.stdout)
        assert payload["adjudication"]["errors"] == 0
        assert payload["adjudication"]["adjudicated"] == len(payload["findings"])
        assert all(f["reason"] for f in payload["findings"])
        assert "adjudicated" in result.stderr

    def test_audit_without_a_key_says_so_and_still_reports(self, tmp_path):
        result = self.run("audit", str(EXAMPLE), "--adjudicate", "--format", "json")
        assert result.returncode == 1
        payload = json.loads(result.stdout)
        assert payload["findings"], "findings are reported with no model configured"
        assert payload["adjudication"]["model"] == "null"
        assert "no model configured" in result.stderr

    def test_ai_status_reports_configuration_without_the_key(self, endpoint, tmp_path):
        result = self.run(
            "ai", "--json", env_extra=env_for(endpoint, tmp_path / "cache")
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["configured"] is True
        assert "mock-key" not in result.stdout
        assert len(payload["key_fingerprint"]) == 12

    def test_ai_check_makes_one_live_request(self, endpoint, tmp_path):
        before = Handler.requests_served
        result = self.run(
            "ai", "--check", env_extra=env_for(endpoint, tmp_path / "cache")
        )
        assert result.returncode == 0, result.stderr
        assert "live check OK" in result.stdout
        assert Handler.requests_served == before + 1

    def test_ai_check_fails_loudly_when_the_endpoint_is_down(self, tmp_path):
        result = self.run(
            "ai", "--check",
            env_extra={
                "PRAHARI_API_KEY": "mock-key",
                "PRAHARI_API_BASE": "http://127.0.0.1:1",
                "PRAHARI_AI_RETRIES": "0",
                "PRAHARI_AI_TIMEOUT": "2",
            },
        )
        assert result.returncode == 1
        assert "live check FAILED" in result.stderr
