"""Path slicing -- turning a finding into a minimal, self-contained excerpt.

The slice is useful with or without a model. It is what the findings panel
shows, what a code review comment quotes, and what an adjudicator would receive
instead of a whole file.

The size argument is the point: the enclosing functions of a cross-file taint
path routinely total thousands of lines, while the path itself is tens. Slicing
is what keeps the reviewed context proportional to the defect rather than to
the codebase.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..diagnostics import Finding
from ..index import SemanticIndex


@dataclass
class Slice:
    """A path rendered as prompt- and review-ready text."""

    cwe: str
    text: str
    line_count: int
    enclosing_line_count: int
    summaries: list[str] = field(default_factory=list)

    @property
    def reduction(self) -> float:
        """Fraction of the enclosing code the slice removes."""
        if not self.enclosing_line_count:
            return 0.0
        return 1.0 - (self.line_count / self.enclosing_line_count)


def slice_finding(finding: Finding, index: SemanticIndex) -> Slice:
    """Render one finding as a compact source-to-sink excerpt."""
    lines: list[str] = [f"CANDIDATE: {finding.path.cwe} ({finding.title.split(': ', 1)[-1]})", "", "PATH:"]
    for step in finding.path.steps:
        snippet = step.snippet or step.value
        lines.append(
            f"  [{step.kind:<9}] {step.location.file}:{step.location.line:<5} {snippet}"
        )
        lines.append(f"  {'':<12} {'':<5}   {step.explanation}")

    summaries: list[str] = []
    if index.interprocedural is not None:
        involved = {
            name
            for name, summary in index.summaries.items()
            if summary.param_flows or summary.reaches_sink
        }
        for name in sorted(involved):
            if any(name in (s.explanation or "") for s in finding.path.steps):
                summaries.append(index.summaries[name].describe())

    if summaries:
        lines.append("")
        lines.append("FUNCTION SUMMARIES:")
        lines.extend(f"  {s}" for s in summaries)

    lines.append("")
    if finding.path.guards:
        lines.append("GUARDS ON PATH:")
        lines.extend(
            f"  {g.condition}  (line {g.location.line})" for g in finding.path.guards
        )
    else:
        lines.append("GUARDS ON PATH: none")

    text = "\n".join(lines)
    enclosing = _enclosing_line_count(finding, index)
    return Slice(
        cwe=finding.path.cwe,
        text=text,
        line_count=len({s.location.line for s in finding.path.steps}),
        enclosing_line_count=enclosing,
        summaries=summaries,
    )


def _enclosing_line_count(finding: Finding, index: SemanticIndex) -> int:
    """Total lines of every file the path touches -- the unsliced baseline."""
    files = {step.location.file for step in finding.path.steps}
    return sum(len(index.source_lines.get(f, [])) for f in files)
