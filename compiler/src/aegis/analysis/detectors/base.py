"""Detector base class and registry.

A detector owns the *knowledge* about one weakness class -- what it is called,
how severe it is, what control is missing, how to fix it -- and contributes any
specification entries its sinks need. It owns no analysis: the taint engine and
the heap state machine do that work, and a detector turns their raw output into
a reportable :class:`~aegis.diagnostics.Finding`.

Adding a seventh CWE therefore costs a specification entry and a description,
not a new analysis engine. That separation is the point of the architecture.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ...diagnostics import (
    Finding,
    Location,
    PropagationStep,
    Severity,
    TaintPath,
)
from ..specs import FuncSpec


class Detector(ABC):
    """Metadata and rendering for one weakness class."""

    cwe: str = ""
    name: str = ""
    severity: Severity = Severity.WARNING
    #: Short statement of what protection is absent when this fires.
    missing_control: str = ""
    #: Concrete remediation, phrased as an instruction.
    remediation: str = ""
    #: SARIF ``precision`` hint, used to rank findings.
    precision: str = "medium"
    help_uri: str = ""

    @property
    def rule_id(self) -> str:
        return f"aegis/{self.cwe.lower().replace('-', '')}"

    def specs(self) -> list[FuncSpec]:
        """Specification entries this detector needs. Usually empty."""
        return []

    @abstractmethod
    def describe(self, context: dict) -> str:
        """One-sentence statement of the specific defect found."""

    # -- shared rendering ---------------------------------------------------

    def finding_from_taint(self, taint_result, hit, source_lines, function: str = "") -> Finding:
        """Build a Finding from a taint sink hit and its reconstructed path."""
        steps: list[PropagationStep] = []
        for index, (key, instr, why) in enumerate(taint_result.path_to(hit)):
            loc = instr.loc if instr is not None else hit.location
            steps.append(
                PropagationStep(
                    kind="SOURCE" if index == 0 else "PROPAGATE",
                    location=loc,
                    value=key,
                    snippet=_snippet(source_lines, loc),
                    explanation=why,
                )
            )
        steps.append(
            PropagationStep(
                kind="SINK",
                location=hit.location,
                value=hit.key,
                snippet=_snippet(source_lines, hit.location),
                explanation=hit.note or f"tainted value reaches {hit.instr.func}()",
            )
        )
        steps = _collapse(steps)

        path = TaintPath(
            cwe=self.cwe,
            source=steps[0].location,
            sink=hit.location,
            steps=steps,
            guards=_readable_guards(
                taint_result.analysis.guards_dominating(hit.block), source_lines
            ),
        )
        context = {
            "function": hit.instr.func,
            "argument_index": hit.argument_index,
            "key": hit.key,
            "steps": len(steps),
            "spec_origin": hit.spec_origin,
        }
        return Finding(
            path=path,
            rule_id=self.rule_id,
            function=function,
            title=f"{self.cwe}: {self.name}",
            message=self.describe(context),
            severity=self.severity,
            missing_control=self.missing_control,
            remediation=self.remediation,
        )

    def finding_from_event(self, event, source_lines, function: str = "") -> Finding:
        """Build a Finding from a heap state machine event."""
        steps = [
            PropagationStep(
                kind="SOURCE",
                location=event.allocation,
                value=event.key,
                snippet=_snippet(source_lines, event.allocation),
                explanation="allocation created here",
            ),
            PropagationStep(
                kind="SINK",
                location=event.location,
                value=event.key,
                snippet=_snippet(source_lines, event.location),
                explanation=event.detail,
            ),
        ]
        path = TaintPath(
            cwe=self.cwe,
            source=event.allocation,
            sink=event.location,
            steps=steps,
        )
        return Finding(
            path=path,
            rule_id=self.rule_id,
            function=function,
            title=f"{self.cwe}: {self.name}",
            message=self.describe({"detail": event.detail, "key": event.key}),
            severity=self.severity,
            missing_control=self.missing_control,
            remediation=self.remediation,
        )


def _snippet(source_lines: dict[str, list[str]], loc: Location) -> str:
    lines = source_lines.get(loc.file) or []
    if 1 <= loc.line <= len(lines):
        return lines[loc.line - 1].strip()
    return ""


def _collapse(steps: list[PropagationStep]) -> list[PropagationStep]:
    """Merge consecutive steps that land on the same source line.

    One source line lowers to several IR instructions, so a path can cross the
    same line twice. Showing it twice makes the trace look like it is repeating
    itself; the later step wins because it carries the more specific role.
    """
    out: list[PropagationStep] = []
    for step in steps:
        if out and (out[-1].location.file, out[-1].location.line) == (
            step.location.file,
            step.location.line,
        ):
            kind = out[-1].kind if out[-1].kind == "SOURCE" else step.kind
            explanation = (
                out[-1].explanation
                if step.explanation == out[-1].explanation
                else f"{out[-1].explanation}, then {step.explanation}"
            )
            out[-1] = PropagationStep(
                kind=kind,
                location=step.location,
                value=step.value,
                snippet=step.snippet,
                explanation=explanation,
            )
            continue
        out.append(step)
    return out


def _readable_guards(guards, source_lines: dict[str, list[str]]):
    """Render each guard as its source text rather than as an SSA temporary."""
    from ...diagnostics import Guard

    out = []
    for guard in guards:
        text = _snippet(source_lines, guard.location) or guard.condition
        out.append(Guard(location=guard.location, condition=text))
    return out


class DetectorRegistry:
    """All registered detectors, indexed by CWE."""

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self._by_cwe: dict[str, Detector] = {}
        for detector in detectors or []:
            self.register(detector)

    def register(self, detector: Detector) -> None:
        self._by_cwe[detector.cwe] = detector

    def get(self, cwe: str) -> Detector | None:
        return self._by_cwe.get(cwe)

    def all(self) -> list[Detector]:
        return sorted(self._by_cwe.values(), key=lambda d: d.cwe)

    def specs(self) -> list[FuncSpec]:
        out: list[FuncSpec] = []
        for detector in self._by_cwe.values():
            out.extend(detector.specs())
        return out

    def __len__(self) -> int:
        return len(self._by_cwe)
