"""The deterministic gateway.

``NullGateway`` answers every request with a fixed verdict. It is not a
placeholder to be deleted later -- it is a permanent component with three jobs:

1. **The system works without a model.** The full pipeline -- parse, IR, SSA,
   dataflow, taint, detectors, SARIF -- runs and produces findings with no
   model configured and no network access.
2. **It is the control configuration for evaluation.** Comparing a real
   adjudicator against ``NullGateway`` is what isolates the model's
   contribution from the static analysis's contribution. Without a control row
   the ablation measures nothing.
3. **It makes CI deterministic.** Model output varies run to run; a test suite
   that depends on it is not a test suite.
"""
from __future__ import annotations

from .base import GatewayResponse


class NullGateway:
    """Returns a fixed, honest non-answer for every request."""

    model_id = "null"

    def __init__(self, verdict: bool = True, confidence: float = 0.5, reason: str = "") -> None:
        self.verdict = verdict
        self.confidence = confidence
        #: Why no live gateway was built -- no key, a refused paid model, an
        #: unknown provider. Empty when NullGateway was chosen deliberately.
        self.reason = reason
        self.calls = 0

    @property
    def available(self) -> bool:
        return True

    def complete(
        self,
        system: str,
        user: str,
        schema: dict | None = None,
        temperature: float = 0.0,
    ) -> GatewayResponse:
        self.calls += 1
        return GatewayResponse(
            data={
                "exploitable": self.verdict,
                "confidence": self.confidence,
                "reason": "no adjudicator configured; static analysis verdict retained",
                "missing_control": "",
            },
            model=self.model_id,
            cached=False,
            latency_ms=0.0,
        )
