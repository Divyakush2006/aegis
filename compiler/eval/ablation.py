"""The ablation matrix -- what each layer of the pipeline actually contributes.

Each configuration adds exactly one component to the one above it, so the
change in detection rate and false positive rate between adjacent rows is
attributable to that component and nothing else.

The first row is the one that matters most. **Pattern matching** reports every
call to a dangerous function by name, using the same parser and the same
specification table as every other row, and nothing else. It is the "grep for
``strcpy``" baseline, and the gap between it and the taint rows is the
quantified answer to *what does the dataflow analysis buy you*.

The last row runs adjudication through ``NullGateway``. With no model
configured it must reproduce the static result exactly. That is not a
placeholder result -- it is the control the ablation needs: any future
adjudicator is measured as a delta against this row, so the model's
contribution is never confused with the analysis's.

Run: ``python eval/ablation.py [corpus_dir]``
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.analysis.detectors import DEFAULT_REGISTRY  # noqa: E402
from aegis.analysis.specs import SpecTable  # noqa: E402
from aegis.diagnostics import Finding, Severity, TaintPath  # noqa: E402
from aegis.index import build_index  # noqa: E402
from aegis.ir import instructions as I  # noqa: E402

from harness import (  # noqa: E402
    CaseResult,
    RunResult,
    classify_function,
    expected_cwe,
    variant_of,
)


# --- Configuration 1: pattern matching, no dataflow -------------------------


def pattern_findings(index) -> list[Finding]:
    """Report every call to a function with a sink specification.

    Deliberately ignores taint, guards, sanitizers and reachability -- this is
    what a name-based linter sees. It reuses the real front end so that the
    comparison isolates the *analysis*, not the parser.
    """
    findings: list[Finding] = []
    for name, cfg in index.cfgs.items():
        for block in cfg:
            for instr in block.all_instrs:
                if not isinstance(instr, I.Call):
                    continue
                spec = index.specs.get(instr.func)
                if spec is None or not spec.sinks:
                    continue
                cwe = spec.sinks[0][1]
                detector = DEFAULT_REGISTRY.get(cwe)
                findings.append(
                    Finding(
                        path=TaintPath(cwe=cwe, source=instr.loc, sink=instr.loc),
                        rule_id=f"pattern/{cwe.lower()}",
                        function=name,
                        title=f"{cwe} (pattern)",
                        message=f"call to {instr.func}()",
                        severity=detector.severity if detector else Severity.WARNING,
                    )
                )
    # Allocation-style weaknesses have no sink specification; a name-based
    # checker flags every malloc as a potential leak.
    for name, cfg in index.cfgs.items():
        for block in cfg:
            for instr in block.all_instrs:
                if isinstance(instr, I.Call) and instr.func in ("malloc", "calloc", "strdup"):
                    for cwe in ("CWE-401", "CWE-476"):
                        findings.append(
                            Finding(
                                path=TaintPath(cwe=cwe, source=instr.loc, sink=instr.loc),
                                rule_id=f"pattern/{cwe.lower()}",
                                function=name,
                                title=f"{cwe} (pattern)",
                                message=f"allocation via {instr.func}()",
                                severity=Severity.WARNING,
                            )
                        )
    return findings


# --- Configurations ---------------------------------------------------------


@dataclass
class Configuration:
    label: str
    adds: str
    kwargs: dict
    pattern_only: bool = False
    adjudicate: bool = False


CONFIGURATIONS = [
    Configuration(
        "Pattern matching only",
        "baseline: dangerous function names",
        {"run_taint": False, "run_memory": False},
        pattern_only=True,
    ),
    Configuration(
        "+ intraprocedural taint",
        "taint lattice over SSA",
        {"run_memory": False, "interprocedural": False},
    ),
    Configuration(
        "+ interprocedural summaries",
        "call graph, bottom-up summaries",
        {"run_memory": False, "interprocedural": True},
    ),
    Configuration(
        "+ heap state machine",
        "allocation lattice (full static)",
        {"run_memory": True, "interprocedural": True},
    ),
    Configuration(
        "+ adjudication (NullGateway)",
        "control: no model configured",
        {"run_memory": True, "interprocedural": True},
        adjudicate=True,
    ),
]


def _roots(index):
    import networkx as nx

    callgraph = index.callgraph
    owners: dict[str, set[str]] = {}
    for name in index.cfgs:
        if classify_function(name) is None:
            continue
        owners.setdefault(name, set()).add(name)
        if callgraph is not None and name in callgraph.graph:
            for reachable in nx.descendants(callgraph.graph, name):
                owners.setdefault(reachable, set()).add(name)
    attribution = {}
    for function, roots in owners.items():
        named = {r for r in roots if classify_function(r) is not None}
        if len(named) == 1:
            attribution[function] = next(iter(named))
    return attribution


def score(corpus: Path, config: Configuration) -> RunResult:
    result = RunResult(label=config.label)
    for path in sorted(corpus.rglob("*.c")):
        cwe = expected_cwe(path)
        if cwe is None:
            continue
        index = build_index([str(path)], specs=SpecTable(), **config.kwargs)

        if config.pattern_only:
            index.findings = pattern_findings(index)
        if config.adjudicate:
            from aegis.ai.adjudicator import Adjudicator
            from aegis.ai.gateway.null import NullGateway

            Adjudicator(NullGateway()).run(index)
            index.findings = [f for f in index.findings if f.exploitable is not False]

        attribution = _roots(index)
        reported = {
            attribution.get(f.function, f.function)
            for f in index.findings
            if f.path.cwe == cwe
        }
        result.files_scored += 1
        for name in sorted(index.cfgs):
            kind = classify_function(name)
            if kind is None:
                continue
            case = CaseResult(
                file=path.name,
                cwe=cwe,
                variant=variant_of(path),
                function=name,
                kind=kind,
                detected=name in reported,
            )
            result.cases.append(case)
            result.metrics.add(case.outcome)
    return result


def run_matrix(corpus: Path) -> list[tuple[Configuration, RunResult]]:
    return [(config, score(corpus, config)) for config in CONFIGURATIONS]


def format_ablation(rows: list[tuple[Configuration, RunResult]]) -> str:
    lines = [
        "| Configuration | TP | FP | FN | TN | Detection | FPR | Precision | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for config, result in rows:
        m = result.metrics
        lines.append(
            f"| {config.label} | {m.tp} | {m.fp} | {m.fn} | {m.tn} | "
            f"{m.detection_rate:.1%} | {m.false_positive_rate:.1%} | "
            f"{m.precision:.1%} | {m.f1:.2f} |"
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    corpus = Path(argv[1]) if len(argv) > 1 else Path(__file__).parent / "corpus"
    rows = run_matrix(corpus)

    print(f"Ablation over {corpus}  ({rows[0][1].files_scored} test cases)\n")
    print(format_ablation(rows))

    print("\nWhat each row adds:")
    for config, _ in rows:
        print(f"  {config.label:32} {config.adds}")

    baseline = rows[0][1].metrics
    full = rows[3][1].metrics
    print(
        f"\nPattern matching -> full static analysis: "
        f"FPR {baseline.false_positive_rate:.1%} -> {full.false_positive_rate:.1%}, "
        f"precision {baseline.precision:.1%} -> {full.precision:.1%}, "
        f"detection {baseline.detection_rate:.1%} -> {full.detection_rate:.1%}"
    )

    out = Path(__file__).parent / "ablation.json"
    out.write_text(
        json.dumps(
            {
                "corpus": str(corpus),
                "configurations": [
                    {"label": c.label, "adds": c.adds, **r.metrics.as_dict()} for c, r in rows
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
