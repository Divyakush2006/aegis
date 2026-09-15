"""Model discovery, for providers that publish a catalogue.

OpenRouter routes to hundreds of models and the roster changes weekly, so
hard-coding a list of ids into a compiler would be wrong within a month. This
asks the provider what the key can actually reach and reports it with the two
facts that decide whether a model is usable here:

* **tool support** -- the adjudicator forces a function call to get a
  schema-valid verdict. A model without it falls back to parsing prose, which
  works but is a weaker contract.
* **price** -- an audit issues one request per finding, so a per-token price
  difference of 30x is a real operational difference, not a rounding error.

Discovery is a convenience, never a dependency: it is used by ``aegis ai
--models`` and by the benchmark, and nothing in the audit path calls it.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

#: Providers whose catalogue endpoint this module knows about.
CATALOGUE_PATHS = {"openrouter": "/models"}


@dataclass
class ModelInfo:
    """One entry from a provider's catalogue."""

    id: str
    name: str = ""
    context_length: int = 0
    prompt_price: float = 0.0      # USD per token
    completion_price: float = 0.0  # USD per token
    supports_tools: bool = False
    description: str = ""

    @property
    def price_per_million(self) -> float:
        """Blended USD per million tokens, weighted for this workload.

        Adjudication prompts are long (a sliced path plus summaries) and
        replies are short (a four-field verdict), so a 10:1 input-to-output
        weighting reflects the real cost far better than a plain average.
        """
        return (self.prompt_price * 10 + self.completion_price) / 11 * 1_000_000

    def cost_for(self, input_tokens: int, output_tokens: int) -> float:
        return input_tokens * self.prompt_price + output_tokens * self.completion_price

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "context_length": self.context_length,
            "supports_tools": self.supports_tools,
            "usd_per_million_blended": round(self.price_per_million, 4),
        }


def fetch_models(
    base_url: str,
    api_key: str = "",
    provider: str = "openrouter",
    timeout: float = 20.0,
    opener=None,
) -> list[ModelInfo]:
    """Fetch the provider's catalogue. Raises nothing the caller cannot handle."""
    path = CATALOGUE_PATHS.get(provider)
    if path is None:
        raise ValueError(f"no catalogue endpoint is known for provider {provider!r}")

    url = f"{base_url.rstrip('/')}{path}"
    headers = {"accept": "application/json", "user-agent": "aegis-compiler/0.1.0"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with (opener or urllib.request.urlopen)(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"catalogue request failed ({error.code})") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError(f"cannot reach the catalogue endpoint: {error}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"malformed catalogue response: {error}") from error

    return [_parse(entry) for entry in payload.get("data", []) if isinstance(entry, dict)]


def _parse(entry: dict) -> ModelInfo:
    pricing = entry.get("pricing") or {}
    parameters = entry.get("supported_parameters") or []
    architecture = entry.get("architecture") or {}
    return ModelInfo(
        id=str(entry.get("id", "")),
        name=str(entry.get("name", "")),
        context_length=int(entry.get("context_length") or 0),
        prompt_price=_price(pricing.get("prompt")),
        completion_price=_price(pricing.get("completion")),
        # OpenRouter advertises capability two ways depending on the model.
        supports_tools=("tools" in parameters or "tool_choice" in parameters)
        or bool(architecture.get("instruct_type") == "tools"),
        description=str(entry.get("description", ""))[:200],
    )


def _price(value) -> float:
    """Prices arrive as strings, and ``-1`` means "not published"."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(number, 0.0)


def rank_for_adjudication(
    models: list[ModelInfo], limit: int = 20, free_only: bool = False
) -> list[ModelInfo]:
    """Order the catalogue by fitness for this task.

    Tool support first, because it is the difference between a validated
    verdict and a parsed one; then price, because an audit spends one request
    per finding. This is an ordering of *candidates to try*, not a quality
    judgement -- which model actually judges C dataflow paths well is an
    empirical question, and ``eval/model_bench.py`` is what answers it.

    With ``free_only`` the price axis disappears, so only ``:free`` variants
    are kept and the tie-break becomes context length: a longer window leaves
    more room for a slice plus a reasoning model's thinking.
    """
    if free_only:
        free = [m for m in models if m.id.endswith(":free")]
        free.sort(key=lambda m: (not m.supports_tools, -m.context_length, m.id))
        return free[:limit]
    usable = [m for m in models if m.id and m.price_per_million > 0]
    usable.sort(key=lambda m: (not m.supports_tools, m.price_per_million))
    return usable[:limit]
