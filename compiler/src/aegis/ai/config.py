"""Adjudication configuration.

Resolved from three places, lowest precedence first: a committed ``aegis.toml``,
a git-ignored ``.env``, then the real environment. A developer machine, a CI
runner and a container can therefore all be configured without editing code.
Nothing here reads a hard-coded key and nothing here prints one:
:meth:`AIConfig.describe` reports a fingerprint, never the secret.

Two providers are supported and the right one is usually inferred: an
``sk-or-...`` key means OpenRouter, ``sk-ant-...`` means Anthropic direct. Each
brings its own default endpoint and models, so a pasted key works without any
further configuration.

**Models are chosen per use case, not globally.** Aegis consults a model in two
situations with opposite requirements, and one model cannot be best at both:

* ``review`` -- batch adjudication from the CLI and CI. Latency is irrelevant;
  a wrong dismissal of a real bug is not. Accuracy first.
* ``interactive`` -- the IDE's *Review Findings with AI*. A developer is
  waiting, so time to verdict matters as much as depth.

Both roles share an ordered list of ``fallback`` models on different providers,
because free endpoints are rate-limited and occasionally down, and a second
opinion that is unavailable half the time is not a feature.

**Free-only is enforced, not requested.** With ``free_only`` on -- the default
for OpenRouter -- a model id without the ``:free`` suffix is refused before a
request is built, whether it came from ``.env``, ``aegis.toml`` or a command
line flag. A typo cannot turn into a bill.

The important property is that an *unconfigured* installation is a valid
installation. :func:`load_config` returns a config with ``enabled = False`` when
no key is present, the gateway factory hands back ``NullGateway``, and the
pipeline runs exactly as it does in CI. Adjudication is an enhancement to the
compiler's verdict, never a dependency of it.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

#: Environment variables consulted for the credential, in priority order.
#: ``AEGIS_API_KEY`` is checked first so a user can point Aegis at a different
#: key from the one their other tooling uses.
KEY_VARIABLES = ("AEGIS_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY")

#: The provider a vendor-named variable implies, used when the key itself has
#: no recognisable prefix.
KEY_VARIABLE_PROVIDERS = {
    "OPENROUTER_API_KEY": "openrouter",
    "ANTHROPIC_API_KEY": "anthropic",
}

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_API_VERSION = "2023-06-01"

#: The use cases a model is chosen for. See the module docstring.
ROLES = ("review", "interactive")

#: OpenRouter's convention for a zero-price variant of a model.
FREE_SUFFIX = ":free"

#: Per-provider defaults, applied only when the user has not chosen explicitly.
#:
#: The OpenRouter model choices are the output of a measurement, not a
#: preference, in three stages: published benchmarks narrowed the free
#: catalogue; a live forced-tool-call probe removed models that were gated or
#: congested; and ``eval/model_bench.py`` ranked the survivors against this
#: project's ground truth. ``docs/AI.md`` records the evidence for each choice.
#:
#: Nemotron 3 Ultra serves both roles because it was the only candidate to
#: complete every benchmark review without an error (8/8 verdicts through the
#: tool). The roles still differ where it matters: ``interactive`` runs it at
#: low reasoning effort for time-to-verdict. The fallbacks are deliberately on
#: other providers, so one provider's outage cannot take out the whole chain.
PROVIDER_DEFAULTS = {
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-5",
        "free_only": False,
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
        "interactive_model": "nvidia/nemotron-3-ultra-550b-a55b:free",
        "fallback_models": (
            "cohere/north-mini-code:free",
            "dots-studio/dots-3-note-preview:free",
        ),
        "free_only": True,
        # Free tier: 20 requests/minute. Pacing slightly under it means a burst
        # never becomes a 429, and a 429 is a request spent for nothing.
        "requests_per_minute": 16.0,
        # Reasoning models spend tokens thinking before they answer; a budget
        # sized for the verdict alone truncates before the tool call arrives.
        "max_tokens": 8192,
        "timeout": 120.0,
        "reasoning_effort": "medium",
        "interactive_reasoning_effort": "low",
    },
}

#: Key prefixes that identify a provider without being told. A user who pastes
#: an OpenRouter key should not also have to set a provider variable to make it
#: work -- and a key sent to the wrong endpoint is a confusing 401, not an
#: obvious mistake.
KEY_PREFIXES = (("sk-or-", "openrouter"), ("sk-ant-", "anthropic"))

#: Config file names searched upward from the working directory.
CONFIG_NAMES = ("aegis.toml", ".aegis.toml")

#: Secrets file names searched upward from the working directory. Unlike
#: ``aegis.toml`` this one *may* carry a credential: it is git-ignored, which
#: is the whole difference.
ENV_NAMES = (".env", ".env.local")

REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high")


def is_free_model(model_id: str) -> bool:
    """True for an OpenRouter zero-price variant."""
    return bool(model_id) and model_id.strip().endswith(FREE_SUFFIX)


@dataclass
class AIConfig:
    """Everything the gateway needs, and nothing the analyses need."""

    provider: str = "anthropic"
    #: The ``review`` model: batch adjudication from the CLI and CI.
    model: str = DEFAULT_MODEL
    #: The ``interactive`` model: the IDE. Empty means "use ``model``".
    interactive_model: str = ""
    #: Tried in order when the primary model is rate-limited or unavailable.
    fallback_models: tuple[str, ...] = ()
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    api_version: str = DEFAULT_API_VERSION

    max_tokens: int = 1024
    temperature: float = 0.0
    timeout: float = 30.0
    max_retries: int = 3

    #: Hard ceiling on requests per run. A compiler that silently spends money
    #: or quota proportional to the size of a codebase is not a tool anyone
    #: deploys, so the limit is on by default rather than opt-in.
    max_requests: int = 200

    #: Client-side pacing; 0 disables it.
    requests_per_minute: float = 0.0

    #: Refuse any model that is not a zero-price variant.
    free_only: bool = False

    #: How much a reasoning model may think, per role. Empty sends nothing and
    #: leaves the provider default.
    reasoning_effort: str = ""
    interactive_reasoning_effort: str = ""

    cache_enabled: bool = True
    cache_dir: Path | None = None

    #: Redact absolute paths from prompts. Slices are code excerpts; the file
    #: system layout around them is not needed to judge exploitability.
    redact_paths: bool = True

    #: Only used by the OpenRouter provider; harmless elsewhere.
    require_tools: bool = False

    #: Which use case this configuration was resolved for.
    role: str = "review"

    #: Populated by :func:`load_config` with where each value came from, so
    #: ``aegis ai`` can explain itself.
    sources: dict[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    @property
    def enabled(self) -> bool:
        """True when a live gateway should be built."""
        return self.configured and self.provider != "null"

    def detected_provider(self) -> str | None:
        """The provider implied by the key's prefix, if it implies one."""
        for prefix, provider in KEY_PREFIXES:
            if self.api_key.startswith(prefix):
                return provider
        return None

    @property
    def key_fingerprint(self) -> str:
        """A stable, non-reversible identifier for the configured key.

        Printed instead of the key so a bug report, a CI log or a screen share
        can confirm *which* credential was used without disclosing it.
        """
        if not self.api_key:
            return "-"
        return hashlib.sha256(self.api_key.encode()).hexdigest()[:12]

    # -- roles ---------------------------------------------------------------

    def for_role(self, role: str) -> "AIConfig":
        """A copy resolved for one use case.

        The review configuration is the base; ``interactive`` swaps in its own
        model and reasoning effort when they are set. Everything else --
        credential, fallbacks, budget, free-only -- is shared, so a guarantee
        made for one role cannot be forgotten by the other.
        """
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
        clone = dataclasses.replace(self, sources=dict(self.sources), role=role)
        if role == "interactive":
            clone.model = self.interactive_model or self.model
            clone.reasoning_effort = self.interactive_reasoning_effort or self.reasoning_effort
        return clone

    def models_in_order(self) -> list[str]:
        """The primary model followed by its fallbacks, without duplicates."""
        ordered: list[str] = []
        for model in (self.model, *self.fallback_models):
            if model and model not in ordered:
                ordered.append(model)
        return ordered

    def free_only_violations(self) -> list[str]:
        """Every configured model that would break the free-only guarantee."""
        if not self.free_only:
            return []
        candidates = [self.model, self.interactive_model, *self.fallback_models]
        return [m for m in dict.fromkeys(candidates) if m and not is_free_model(m)]

    # -- paths and reporting -------------------------------------------------

    def resolved_cache_dir(self) -> Path:
        if self.cache_dir is not None:
            return Path(self.cache_dir)
        root = os.environ.get("XDG_CACHE_HOME") or os.environ.get("LOCALAPPDATA")
        base = Path(root) if root else Path.home() / ".cache"
        return base / "aegis" / "adjudication"

    def describe(self) -> dict:
        """A printable summary. Contains no secret material by construction."""
        return {
            "provider": self.provider,
            "model": self.model,
            "interactive_model": self.interactive_model or self.model,
            "fallback_models": list(self.fallback_models),
            "free_only": self.free_only,
            "free_only_violations": self.free_only_violations(),
            "configured": self.configured,
            "key_fingerprint": self.key_fingerprint,
            "base_url": self.base_url,
            "reasoning_effort": self.reasoning_effort or "provider default",
            "interactive_reasoning_effort": (
                self.interactive_reasoning_effort or self.reasoning_effort or "provider default"
            ),
            "requests_per_minute": self.requests_per_minute or "unpaced",
            "timeout_seconds": self.timeout,
            "max_tokens": self.max_tokens,
            "max_retries": self.max_retries,
            "max_requests": self.max_requests,
            "cache": str(self.resolved_cache_dir()) if self.cache_enabled else "disabled",
            "redact_paths": self.redact_paths,
            "require_tools": self.require_tools,
            "sources": dict(self.sources),
        }


def _find_config_file(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _read_toml(path: Path) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            return {}
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except Exception:
        return {}
    section = data.get("tool", {}).get("aegis", {}).get("ai", {})
    return section if isinstance(section, dict) else {}


def _find_env_file(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        for name in ENV_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a ``.env`` file into a mapping.

    Deliberately small: ``KEY=value`` per line, ``#`` comments, optional
    ``export`` prefix, and quotes stripped. No interpolation and no shell
    evaluation -- a configuration file that can execute anything is a
    configuration file that can execute the wrong thing.

    A malformed line is skipped rather than raising. The file holds a
    credential, so failing to parse it must not print its contents in a
    traceback.
    """
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, separator, value = line.partition("=")
        if not separator:
            continue
        name = name.strip()
        if not name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            # An unquoted trailing comment is a comment, not part of a key.
            value = value.split(" #", 1)[0].rstrip()
        values[name] = value
    return values


def _to_float(raw, fallback: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return fallback


def _to_int(raw, fallback: int) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return fallback


def _to_bool(raw, fallback: bool) -> bool:
    if raw is None:
        return fallback
    return str(raw).strip().lower() not in {"0", "false", "no", "off", ""}


def _to_models(raw, fallback) -> tuple[str, ...]:
    if isinstance(raw, (list, tuple)):
        items = raw
    else:
        items = str(raw).split(",")
    return tuple(item.strip() for item in items if str(item).strip())


def _to_effort(raw, fallback: str) -> str:
    value = str(raw).strip().lower()
    return value if value in REASONING_EFFORTS else fallback


def load_config(
    start: Path | None = None,
    environ: dict | None = None,
    role: str = "review",
) -> AIConfig:
    """Resolve configuration from ``aegis.toml``, then ``.env``, then the environment.

    The ordering is what deployments expect. ``aegis.toml`` holds the choices a
    repository makes for everyone -- models, budget, timeouts -- and is
    committed. ``.env`` holds the developer's credential and is git-ignored.
    The real environment wins over both, so CI and containers inject secrets
    the usual way without a file existing at all.

    ``role`` selects the use case the result is resolved for.
    """
    env = dict(os.environ if environ is None else environ)
    config = AIConfig()
    root = Path(start or Path.cwd())

    # --- 1. the committed file ------------------------------------------
    file_path = _find_config_file(root)
    file_values = _read_toml(file_path) if file_path else {}
    for key, value in file_values.items():
        if hasattr(config, key) and key not in {"api_key", "sources", "role"}:
            if key == "fallback_models":
                value = _to_models(value, ())
            setattr(config, key, value)
            config.sources[key] = str(file_path)
    # A key in a committed file is a leak waiting to happen; accept it only
    # from .env or the environment.
    if "api_key" in file_values:
        config.sources["api_key"] = f"ignored in {file_path} - use .env or an environment variable"

    # --- 2. the git-ignored secrets file --------------------------------
    # AEGIS_NO_DOTENV exists for the test suite: a developer's real key in the
    # project's .env must never turn a test into an API call.
    skip_dotenv = _to_bool(env.get("AEGIS_NO_DOTENV"), False)
    env_path = None if skip_dotenv else _find_env_file(root)
    env_values = read_env_file(env_path) if env_path else {}
    # The real environment wins, so an exported key overrides a stale file.
    settings = {**env_values, **env}
    origin = {
        name: (str(env_path) if name in env_values and name not in env else name)
        for name in settings
    }

    # --- 3. the credential ----------------------------------------------
    key_variable = None
    for variable in KEY_VARIABLES:
        value = (settings.get(variable) or "").strip()
        if value:
            config.api_key = value
            config.sources["api_key"] = origin.get(variable, variable)
            key_variable = variable
            break

    # --- 4. provider, then its defaults ---------------------------------
    if settings.get("AEGIS_AI_PROVIDER"):
        config.provider = settings["AEGIS_AI_PROVIDER"].strip()
        config.sources["provider"] = origin.get("AEGIS_AI_PROVIDER", "AEGIS_AI_PROVIDER")
    elif "provider" not in config.sources:
        by_prefix = config.detected_provider()
        by_variable = KEY_VARIABLE_PROVIDERS.get(key_variable or "")
        if by_prefix:
            config.provider = by_prefix
            config.sources["provider"] = "detected from the key prefix"
        elif by_variable:
            config.provider = by_variable
            config.sources["provider"] = f"implied by {key_variable}"

    defaults = PROVIDER_DEFAULTS.get(config.provider, {})
    for field_name, value in defaults.items():
        # Only fill in what the user has not chosen; an explicit choice in
        # aegis.toml or the environment always wins.
        if field_name not in config.sources:
            setattr(config, field_name, value)

    # --- 5. everything else ---------------------------------------------
    def take(variable: str, attribute: str, convert=None):
        if variable not in settings or settings[variable] == "":
            return
        raw = settings[variable]
        current = getattr(config, attribute)
        setattr(config, attribute, convert(raw, current) if convert else raw.strip())
        config.sources[attribute] = origin.get(variable, variable)

    take("AEGIS_MODEL", "model")
    take("AEGIS_MODEL_INTERACTIVE", "interactive_model")
    take("AEGIS_MODEL_FALLBACKS", "fallback_models", _to_models)
    take("AEGIS_API_BASE", "base_url")
    take("AEGIS_AI_FREE_ONLY", "free_only", _to_bool)
    take("AEGIS_AI_REASONING", "reasoning_effort", _to_effort)
    take("AEGIS_AI_REASONING_INTERACTIVE", "interactive_reasoning_effort", _to_effort)
    take("AEGIS_AI_RPM", "requests_per_minute", _to_float)
    take("AEGIS_AI_CACHE", "cache_enabled", _to_bool)
    take("AEGIS_AI_TIMEOUT", "timeout", _to_float)
    take("AEGIS_AI_RETRIES", "max_retries", _to_int)
    take("AEGIS_AI_MAX_REQUESTS", "max_requests", _to_int)
    take("AEGIS_AI_MAX_TOKENS", "max_tokens", _to_int)
    take("AEGIS_AI_REQUIRE_TOOLS", "require_tools", _to_bool)
    if settings.get("AEGIS_AI_CACHE_DIR"):
        config.cache_dir = Path(settings["AEGIS_AI_CACHE_DIR"])
        config.sources["cache_dir"] = origin.get("AEGIS_AI_CACHE_DIR", "AEGIS_AI_CACHE_DIR")

    config.fallback_models = tuple(config.fallback_models)
    config.base_url = config.base_url.rstrip("/")
    return config.for_role(role) if role != "review" else config
