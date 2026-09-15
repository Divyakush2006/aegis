"""Adjudication -- a second opinion on findings the compiler already produced.

The ordering is the whole argument. The compiler is the detector: taint
analysis, the heap state machine and the detectors decide what a finding *is*.
Adjudication runs afterwards, sees one sliced path at a time, and may only
**demote** -- lower a confidence, mark a path unexploitable, name a missing
control. Three invariants are enforced in code rather than requested in a
prompt:

1. **No finding is created.** The loop iterates over an existing list; there is
   no path by which a response adds an entry.
2. **Confidence never rises.** A verdict is clamped to ``[0, 1]`` and then to
   at most the confidence the static analysis already carried, so the model
   cannot talk a weak result into looking strong.
3. **Severity is untouched.** Ranking and exit codes stay a property of the
   program analysis.

Together these mean a misbehaving or hostile model can cost recall, never
precision -- the direction that matters for a security tool, and the reason the
measured numbers in the evaluation remain attributable to the compiler.

Failure is contained the same way: any gateway error keeps the static verdict
for that finding and records the reason. An audit with no network reaching the
endpoint reports exactly what an unadjudicated audit reports.
"""
from __future__ import annotations

import math
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..diagnostics import Finding
from ..index import SemanticIndex
from .gateway.base import GatewayResponse, ModelGateway
from .gateway.null import NullGateway
from .slicer import slice_finding

SYSTEM_PROMPT = """\
You are reviewing the output of a static analyser for a C compiler. The \
analyser has already proven a dataflow path from an untrusted source to a \
security-sensitive sink; your job is not to find bugs but to judge whether this \
specific path is exploitable as shown.

Rules:
- Judge only the evidence presented. Do not assume code you cannot see.
- If a guard on the path genuinely neutralises the flow, the path is not \
exploitable; say which guard.
- If the evidence is insufficient to tell, the path remains exploitable and \
your confidence should be low. Absence of proof is not proof of safety.
- `missing_control` names the control that should exist (for example "length \
check before the copy"), not a prose explanation.

Answer only by calling the provided tool."""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "exploitable": {
            "type": "boolean",
            "description": "True if the path as shown can be exploited.",
        },
        "reason": {
            "type": "string",
            "description": "One or two sentences citing the specific evidence used.",
        },
        "missing_control": {
            "type": "string",
            "description": "The security control absent from this path, if any.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "Certainty in the verdict, where 1.0 is certain.",
        },
    },
    "required": ["exploitable", "reason", "confidence"],
}

#: Matches Windows and POSIX absolute paths in a slice, so prompts carry file
#: names without disclosing the directory layout they sit in.
_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|/)(?:[\w .+-]+[\\/])+")


@dataclass
class AdjudicationStats:
    """What the pass did, in enough detail to put in a report."""

    candidates: int = 0
    adjudicated: int = 0
    dismissed: int = 0
    demoted: int = 0
    errors: int = 0
    cache_hits: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    mean_reduction: float = 0.0
    elapsed_seconds: float = 0.0
    model: str = "null"
    failures: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "candidates": self.candidates,
            "adjudicated": self.adjudicated,
            "dismissed": self.dismissed,
            "demoted": self.demoted,
            "errors": self.errors,
            "cache_hits": self.cache_hits,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "mean_context_reduction": round(self.mean_reduction, 4),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


class Adjudicator:
    """Reviews candidate findings through a gateway."""

    def __init__(
        self,
        gateway: ModelGateway | None = None,
        max_workers: int = 4,
        redact_paths: bool = True,
    ) -> None:
        self.gateway: ModelGateway = gateway or NullGateway()
        self.max_workers = max(1, max_workers)
        self.redact_paths = redact_paths
        self.stats = AdjudicationStats(model=getattr(self.gateway, "model_id", "null"))

    @property
    def enabled(self) -> bool:
        """True when a real model backs this adjudicator.

        ``NullGateway`` answers without consulting anything, so a run using it
        is the control configuration rather than an adjudicated one. The
        distinction is what makes the ablation table's last row meaningful.
        """
        inner = getattr(self.gateway, "inner", self.gateway)
        return not isinstance(inner, NullGateway)

    # -- the pass -----------------------------------------------------------

    def run(self, index: SemanticIndex) -> list[Finding]:
        """Adjudicate every finding in ``index``, in place, and return them."""
        started = time.perf_counter()
        findings = index.findings
        self.stats.candidates = len(findings)
        if not findings:
            return findings

        slices = [slice_finding(finding, index) for finding in findings]
        reductions = [excerpt.reduction for excerpt in slices]
        prompts = [self._prompt(excerpt.text) for excerpt in slices]

        # Requests are network-bound, so a small pool turns an audit of N
        # findings from N round trips into roughly N/workers. Results are
        # written back by index, so output order stays the compiler's ranking
        # rather than whichever response arrived first.
        if self.max_workers > 1 and len(findings) > 1 and self.enabled:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                outcomes = list(pool.map(self._ask, prompts))
        else:
            outcomes = [self._ask(prompt) for prompt in prompts]

        for finding, outcome in zip(findings, outcomes):
            self._apply(finding, outcome)

        self.stats.mean_reduction = sum(reductions) / len(reductions) if reductions else 0.0
        self.stats.elapsed_seconds = time.perf_counter() - started
        self.stats.cache_hits = getattr(self.gateway, "hits", 0)
        inner = getattr(self.gateway, "inner", self.gateway)
        self.stats.input_tokens = getattr(inner, "input_tokens", 0)
        self.stats.output_tokens = getattr(inner, "output_tokens", 0)
        return findings

    def _prompt(self, text: str) -> str:
        return _redact(text) if self.redact_paths else text

    def _ask(self, prompt: str) -> GatewayResponse | Exception:
        """One request. Exceptions are returned, not raised, so one failed
        finding cannot abandon the rest of the audit."""
        try:
            return self.gateway.complete(
                system=SYSTEM_PROMPT,
                user=prompt,
                schema=VERDICT_SCHEMA,
                temperature=0.0,
            )
        except Exception as error:  # every gateway failure is recoverable here
            return error

    def _apply(self, finding: Finding, outcome: GatewayResponse | Exception) -> None:
        if isinstance(outcome, Exception):
            self.stats.errors += 1
            message = str(outcome)
            if message not in self.stats.failures:
                self.stats.failures.append(message)
            # The static verdict stands, and the record says why no second
            # opinion is attached to it.
            finding.adjudicator = "unavailable"
            finding.reason = f"adjudication unavailable: {message}"
            return

        data = outcome.data if isinstance(outcome.data, dict) else {}
        prior = finding.path.confidence

        finding.adjudicator = outcome.model
        finding.exploitable = bool(data.get("exploitable", True))
        finding.reason = str(data.get("reason", "") or "")

        # An unstated confidence is not "unknown" to a reader -- the reporting
        # layer shows it as 1.0, and the reviewer treats the finding as the
        # compiler's unqualified claim. Comparing against that effective value
        # is what makes the invariant mean the same thing in the code and in
        # the report, and what keeps `demoted` agreeing with what a reader of
        # the report would count.
        effective_prior = 1.0 if prior is None else prior
        # Invariant 2: a model may lower confidence, never raise it.
        confidence = min(_clamp(data.get("confidence"), default=1.0), effective_prior)
        if confidence < effective_prior:
            self.stats.demoted += 1
        finding.path.confidence = confidence

        control = data.get("missing_control")
        # Only fill a gap; the detector's own wording is the authority when it
        # has one, because it is derived from the specification table.
        if control and not finding.missing_control:
            finding.missing_control = str(control)

        self.stats.adjudicated += 1
        if not finding.exploitable:
            self.stats.dismissed += 1


def _clamp(value, default: float = 1.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(number) or math.isinf(number):
        return default
    return max(0.0, min(1.0, number))


def _redact(text: str) -> str:
    """Strip directory prefixes, keeping the file name the path refers to."""
    return _ABSOLUTE_PATH.sub("", text)


def dismissed(findings: list[Finding]) -> list[Finding]:
    """Findings an adjudicator judged unexploitable.

    Kept as a separate query rather than removing them from the index: a
    dismissal is a claim that deserves review, and a tool that silently deletes
    results is one nobody can audit.
    """
    return [f for f in findings if f.exploitable is False]
