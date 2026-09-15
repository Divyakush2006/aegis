"""Evaluation harness: ground truth, scoring, and the exclusion log.

Ground truth follows the NIST Juliet convention, so this harness scores the
generated corpus in ``eval/corpus`` and the real SARD test suite with the same
code and no special casing:

* the expected weakness comes from the ``CWE<n>_`` file name prefix;
* a function whose name begins with ``bad`` contains the flaw;
* a function whose name begins with ``good`` is the safe counterpart.

**Scoring is per function, not per file.** A file holds both the flawed and the
safe variant, so scoring per file would make every case simultaneously a true
positive and a false positive. Per-function scoring is what yields a detection
rate and a false positive rate from one corpus -- the property that makes paired
suites worth using.

Findings raised inside a helper are attributed to the ``bad``/``good`` root that
reaches them, resolved through the call graph. Juliet splits flows across
helpers constantly, and attributing a finding to ``sink_bad`` rather than to
``bad`` would score a correct detection as a miss.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.analysis.specs import SpecTable  # noqa: E402
from aegis.index import SemanticIndex, build_index  # noqa: E402

CWE_IN_NAME = re.compile(r"CWE[-_]?(\d+)")

#: Juliet flow-variant suffix, e.g. ``__01`` ... ``__22``.
VARIANT_IN_NAME = re.compile(r"__(\w+?)(?:\.c)?$")


def expected_cwe(path: Path) -> str | None:
    match = CWE_IN_NAME.search(path.name)
    return f"CWE-{int(match.group(1))}" if match else None


def variant_of(path: Path) -> str:
    match = VARIANT_IN_NAME.search(path.stem)
    return match.group(1) if match else "--"


def classify_function(name: str) -> str | None:
    """``bad``, ``good`` or None for a helper that is neither."""
    lowered = name.lower()
    if lowered.startswith("bad"):
        return "bad"
    if lowered.startswith("good"):
        return "good"
    return None


@dataclass
class CaseResult:
    """One scored (file, root function) pair."""

    file: str
    cwe: str
    variant: str
    function: str
    kind: str  # "bad" | "good"
    detected: bool

    @property
    def outcome(self) -> str:
        if self.kind == "bad":
            return "TP" if self.detected else "FN"
        return "FP" if self.detected else "TN"


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, outcome: str) -> None:
        setattr(self, outcome.lower(), getattr(self, outcome.lower()) + 1)

    @property
    def detection_rate(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = self.fp + self.tn
        return self.fp / total if total else 0.0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return self.tp / total if total else 0.0

    @property
    def recall(self) -> float:
        return self.detection_rate

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class RunResult:
    """Everything one configuration produced over the whole corpus."""

    label: str
    cases: list[CaseResult] = field(default_factory=list)
    metrics: Metrics = field(default_factory=Metrics)
    exclusions: dict[str, int] = field(default_factory=dict)
    parse_failures: list[str] = field(default_factory=list)
    files_scored: int = 0
    elapsed: float = 0.0

    def by_cwe(self) -> dict[str, Metrics]:
        out: dict[str, Metrics] = {}
        for case in self.cases:
            out.setdefault(case.cwe, Metrics()).add(case.outcome)
        return out

    def by_variant(self) -> dict[str, Metrics]:
        out: dict[str, Metrics] = {}
        for case in self.cases:
            out.setdefault(case.variant, Metrics()).add(case.outcome)
        return out

    def failures(self) -> list[CaseResult]:
        return [c for c in self.cases if c.outcome in ("FN", "FP")]


def _roots(index: SemanticIndex) -> dict[str, str]:
    """Map every analysed function to its ``bad``/``good`` root, if it has one.

    A helper reachable from exactly one root is attributed to it. A helper
    reachable from both is attributed to neither, because a finding there cannot
    be scored without ambiguity -- Juliet avoids this by giving each root its
    own helper chain, and so does the generated corpus.
    """
    callgraph = index.callgraph
    roots: dict[str, set[str]] = {}
    for name in index.cfgs:
        kind = classify_function(name)
        if kind is None:
            continue
        roots[name] = {name}
        if callgraph is not None and name in callgraph.graph:
            import networkx as nx

            for reachable in nx.descendants(callgraph.graph, name):
                roots.setdefault(reachable, set()).add(name)

    attribution: dict[str, str] = {}
    for function, owners in roots.items():
        named = {o for o in owners if classify_function(o) is not None}
        if len(named) == 1:
            attribution[function] = next(iter(named))
    return attribution


def score_file(path: Path, **index_kwargs) -> tuple[list[CaseResult], SemanticIndex | None]:
    """Analyse one test case file and score every root function in it."""
    cwe = expected_cwe(path)
    if cwe is None:
        return [], None

    index = build_index([str(path)], specs=SpecTable(), **index_kwargs)
    attribution = _roots(index)

    # Which roots reported the expected weakness?
    reported: set[str] = set()
    for finding in index.findings:
        if finding.path.cwe != cwe:
            continue
        root = attribution.get(finding.function, finding.function)
        if classify_function(root) is not None:
            reported.add(root)

    variant = variant_of(path)
    cases = [
        CaseResult(
            file=path.name,
            cwe=cwe,
            variant=variant,
            function=name,
            kind=classify_function(name),
            detected=name in reported,
        )
        for name in sorted(index.cfgs)
        if classify_function(name) is not None
    ]
    return cases, index


def run(
    corpus: Path, label: str = "full", pattern: str = "*.c", **index_kwargs
) -> RunResult:
    """Score an entire corpus directory under one configuration."""
    import time

    started = time.perf_counter()
    result = RunResult(label=label)

    for path in sorted(corpus.rglob(pattern)):
        cases, index = score_file(path, **index_kwargs)
        if index is None:
            continue
        result.files_scored += 1
        if index.errors():
            result.parse_failures.append(path.name)
        for exclusion in index.exclusions:
            result.exclusions[exclusion.construct] = (
                result.exclusions.get(exclusion.construct, 0) + 1
            )
        for case in cases:
            result.cases.append(case)
            result.metrics.add(case.outcome)

    result.elapsed = round(time.perf_counter() - started, 3)
    return result


def format_metrics_table(rows: dict[str, Metrics], first_column: str = "CWE") -> str:
    header = f"| {first_column} | TP | FP | FN | TN | Detection | FPR | Precision | F1 |"
    divider = "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
    lines = [header, divider]
    for key in sorted(rows):
        m = rows[key]
        lines.append(
            f"| {key} | {m.tp} | {m.fp} | {m.fn} | {m.tn} | "
            f"{m.detection_rate:.1%} | {m.false_positive_rate:.1%} | "
            f"{m.precision:.1%} | {m.f1:.2f} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    corpus_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "corpus"
    outcome = run(corpus_dir)
    m = outcome.metrics
    print(f"corpus: {corpus_dir}  ({outcome.files_scored} files, {len(outcome.cases)} scored functions)")
    print(f"TP={m.tp}  FP={m.fp}  FN={m.fn}  TN={m.tn}")
    print(
        f"detection={m.detection_rate:.1%}  FPR={m.false_positive_rate:.1%}  "
        f"precision={m.precision:.1%}  F1={m.f1:.2f}   [{outcome.elapsed}s]"
    )
    print()
    print(format_metrics_table(outcome.by_cwe()))
    print()
    print(format_metrics_table(outcome.by_variant(), "Flow variant"))
    if outcome.failures():
        print("\nmisses:")
        for case in outcome.failures():
            print(f"  {case.outcome}  {case.file:52} {case.function}")
