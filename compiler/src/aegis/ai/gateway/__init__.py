"""Gateway construction.

One factory, one rule: **an unconfigured install is a working install.** If no
credential is present, the provider is unknown, a model would break the
free-only guarantee, or constructing the live client fails for any reason at
all, this returns :class:`NullGateway` -- carrying the reason -- and the audit
proceeds on the compiler's own verdict. Callers that need to know whether a
model was actually consulted read ``Adjudicator.enabled`` or the
``adjudicator`` field recorded on each finding; callers that need to tell the
user *why* not read ``NullGateway.reason``. None of them has to handle a
missing gateway.
"""
from __future__ import annotations

from ..config import AIConfig, is_free_model, load_config
from .base import GatewayResponse, ModelGateway
from .cache import CachingGateway
from .null import NullGateway

__all__ = [
    "AIConfig",
    "CachingGateway",
    "GatewayResponse",
    "ModelGateway",
    "NullGateway",
    "PROVIDERS",
    "build_gateway",
    "is_free_model",
    "load_config",
]

#: Providers this build can talk to, for error messages and ``aegis ai``.
PROVIDERS = ("anthropic", "openrouter")


def build_gateway(
    config: AIConfig | None = None,
    transport=None,
    use_cache: bool | None = None,
) -> ModelGateway:
    """Return the best gateway the configuration supports.

    ``transport`` is threaded through for tests and for anyone putting a proxy
    in front of the endpoint; it is never needed in normal use.
    """
    config = config or load_config()
    if not config.configured:
        return NullGateway(reason="no API key configured")
    if not config.enabled:
        return NullGateway(reason=f"provider {config.provider!r} is disabled")

    violations = config.free_only_violations()
    if violations:
        # Refused before any request exists. A misconfigured model id must not
        # be discoverable by receiving a bill for it.
        return NullGateway(
            reason=(
                "free-only mode refused non-free model(s): "
                + ", ".join(violations)
                + " -- use ids ending in ':free', or set AEGIS_AI_FREE_ONLY=0"
            )
        )

    builder = _BUILDERS.get(config.provider)
    if builder is None:
        # An unknown provider is a configuration mistake, not a crash: report
        # it by behaving exactly as an unconfigured install does.
        return NullGateway(
            reason=f"unknown provider {config.provider!r}; expected one of {PROVIDERS}"
        )

    from .http import GatewayError

    try:
        gateway: ModelGateway = builder(config, transport)
    except GatewayError as error:
        return NullGateway(reason=str(error))

    wants_cache = config.cache_enabled if use_cache is None else use_cache
    if wants_cache:
        gateway = CachingGateway(gateway, config.resolved_cache_dir())
    return gateway


def _common(config: AIConfig, transport) -> dict:
    return {
        "api_key": config.api_key,
        "model": config.model,
        "base_url": config.base_url,
        "max_tokens": config.max_tokens,
        "timeout": config.timeout,
        "max_retries": config.max_retries,
        "max_requests": config.max_requests,
        "requests_per_minute": config.requests_per_minute,
        "transport": transport,
    }


def _build_anthropic(config: AIConfig, transport) -> ModelGateway:
    from .anthropic import AnthropicGateway

    return AnthropicGateway(api_version=config.api_version, **_common(config, transport))


def _build_openrouter(config: AIConfig, transport) -> ModelGateway:
    from .openrouter import OpenRouterGateway

    return OpenRouterGateway(
        require_tools=config.require_tools,
        fallback_models=config.fallback_models,
        reasoning_effort=config.reasoning_effort,
        **_common(config, transport),
    )


#: Adding a provider is one entry here plus one module. Nothing in the
#: compiler, the analyses or the CLI changes.
_BUILDERS = {
    "anthropic": _build_anthropic,
    "openrouter": _build_openrouter,
}
