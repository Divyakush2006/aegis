"""Model gateway protocol.

Every path that could consult a language model terminates here, so the model is
a runtime configuration value rather than an architectural commitment. Nothing
in the compiler or the analysis imports anything below this interface.

Two implementations satisfy it. :class:`~aegis.ai.gateway.null.NullGateway`
is deterministic and needs no network; it is what CI and the evaluation control
row run on. :class:`~aegis.ai.gateway.anthropic.AnthropicGateway` calls a real
model. Selecting between them is :func:`~aegis.ai.gateway.build_gateway`'s job
and depends only on configuration, so adding the live path required no change
to any analysis module -- which is the property this interface exists to
protect.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class GatewayResponse:
    """A structured response plus the provenance evaluation needs."""

    data: dict
    model: str
    cached: bool = False
    latency_ms: float = 0.0
    raw: str = ""
    usage: dict = field(default_factory=dict)


@runtime_checkable
class ModelGateway(Protocol):
    """Minimal surface every gateway implementation provides."""

    #: Identifier recorded on every finding, so results are traceable to what
    #: produced them. Without it an ablation table is not reproducible.
    model_id: str

    def complete(
        self,
        system: str,
        user: str,
        schema: dict | None = None,
        temperature: float = 0.0,
    ) -> GatewayResponse:
        """Return a structured completion. Implementations must be synchronous."""
        ...

    @property
    def available(self) -> bool:
        """False when the backing service is not reachable or not configured."""
        ...
