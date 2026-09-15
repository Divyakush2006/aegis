"""The Semantic Index -- the contract between the compiler and everything above it.

One compilation produces one index; the findings renderer, the editor bridge and
any adjudication layer all read from this single structure rather than
re-deriving program facts. Keeping it explicit is what stops the analysis and
the presentation layers from drifting apart, and what makes an audit
reproducible: an index is a pure function of the source revision and the
specification table.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from .analysis import memory as memory_analysis
from .analysis.callgraph import InterproceduralResult, analyse_program
from .analysis.detectors import DEFAULT_REGISTRY, DetectorRegistry
from .analysis.specs import SpecTable
from .diagnostics import Diagnostic, Finding, Severity, UnsupportedConstruct
from .frontend import ast_nodes as A
from .frontend.adapter import parse_source
from .ir import instructions as I
from .ir.cfg import CFG, build_cfgs
from .ir.lowering import lower_program
from .ir.ssa import build_ssa, verify_ssa
from .semantic.checker import TypeChecker

#: Severity ranking used to order findings for presentation.
_SEVERITY_RANK = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.NOTE: 2}
_PRECISION_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Exclusion:
    """One declaration skipped because it falls outside the analysed subset."""

    construct: str
    file: str
    line: int
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "construct": self.construct,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
        }


@dataclass
class SemanticIndex:
    """A queryable snapshot of one compilation."""

    revision: str
    files: list[str] = field(default_factory=list)
    source_lines: dict[str, list[str]] = field(default_factory=dict)
    program: A.Program | None = None
    module: I.Module | None = None
    cfgs: dict[str, CFG] = field(default_factory=dict)
    interprocedural: InterproceduralResult | None = None
    memory: dict[str, memory_analysis.MemoryResult] = field(default_factory=dict)
    specs: SpecTable = field(default_factory=SpecTable)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    exclusions: list[Exclusion] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    # -- accessors ----------------------------------------------------------

    @property
    def summaries(self):
        return self.interprocedural.summaries if self.interprocedural else {}

    @property
    def callgraph(self):
        return self.interprocedural.callgraph if self.interprocedural else None

    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is Severity.ERROR]

    def findings_by_cwe(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for finding in self.findings:
            out.setdefault(finding.path.cwe, []).append(finding)
        return out

    def unmodelled_externals(self) -> set[str]:
        """External calls with no specification.

        This is the work list a specification-inference component consumes, and
        a reportable metric in its own right: it quantifies how much of the
        program the static analysis had to guess about.
        """
        return self.callgraph.unmodelled_externals(self.specs) if self.callgraph else set()


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _revision(sources: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name in sorted(sources):
        digest.update(name.encode())
        digest.update(sources[name].encode())
    return digest.hexdigest()[:16]


def build_index(
    paths: list[str],
    specs: SpecTable | None = None,
    registry: DetectorRegistry = DEFAULT_REGISTRY,
    use_cpp: bool = False,
    run_memory: bool = True,
    run_taint: bool = True,
    interprocedural: bool = True,
) -> SemanticIndex:
    """Run the full pipeline over ``paths`` and return the Semantic Index.

    ``run_taint`` and ``run_memory`` exist so the evaluation harness can build
    an ablation matrix by disabling one analysis at a time without touching any
    other part of the pipeline.
    """
    started = time.perf_counter()
    sources = {p: _read(p) for p in paths}
    index = SemanticIndex(revision=_revision(sources), files=list(sources))
    index.source_lines = {p: text.splitlines() for p, text in sources.items()}
    index.specs = specs or SpecTable()
    for spec in registry.specs():
        index.specs.add(spec)

    # --- front end ---------------------------------------------------------
    merged = A.Program()
    raw_exclusions: list[UnsupportedConstruct] = []
    for path, text in sources.items():
        try:
            program, _pre, excluded = parse_source(text, path, use_cpp=use_cpp)
        except Exception as exc:  # parse failure: record and continue
            index.diagnostics.append(
                Diagnostic(
                    severity=Severity.ERROR,
                    code="parse",
                    message=str(exc).replace("\n", " ")[:300],
                    location=_location_for(path),
                )
            )
            continue
        raw_exclusions.extend(excluded)
        merged.functions.extend(program.functions)
        merged.globals.extend(program.globals)
    index.program = merged

    # --- semantic analysis -------------------------------------------------
    checker = TypeChecker(merged)
    index.diagnostics.extend(checker.run())

    # --- IR, CFG, SSA ------------------------------------------------------
    index.module = lower_program(merged, raw_exclusions)
    index.exclusions = [
        Exclusion(
            construct=e.construct, file=e.location.file, line=e.location.line, detail=e.detail
        )
        for e in raw_exclusions
    ]
    index.cfgs = build_cfgs(index.module)
    build_ssa(index.cfgs)

    ssa_errors: list[str] = []
    for cfg in index.cfgs.values():
        ssa_errors.extend(verify_ssa(cfg))

    # --- analyses ----------------------------------------------------------
    if run_taint:
        index.interprocedural = analyse_program(
            index.module, index.cfgs, index.specs, interprocedural=interprocedural
        )
    if run_memory:
        index.memory = memory_analysis.analyse_program(index.cfgs)

    # --- findings ----------------------------------------------------------
    index.findings = _collect_findings(index, registry)

    index.stats = {
        "files": len(index.files),
        "functions": len(index.cfgs),
        "basic_blocks": sum(len(c) for c in index.cfgs.values()),
        "instructions": sum(
            len(b.all_instrs) for c in index.cfgs.values() for b in c
        ),
        "externals": len(index.callgraph.externals()) if index.callgraph else 0,
        "unmodelled_externals": len(index.unmodelled_externals()),
        "summary_iterations": index.interprocedural.iterations if index.interprocedural else 0,
        "exclusions": len(index.exclusions),
        "ssa_violations": len(ssa_errors),
        "findings": len(index.findings),
        "elapsed_seconds": round(time.perf_counter() - started, 4),
    }
    return index


def _location_for(path: str):
    from .diagnostics import Location

    return Location(path, 1, 1)


def _collect_findings(index: SemanticIndex, registry: DetectorRegistry) -> list[Finding]:
    findings: list[Finding] = []

    if index.interprocedural is not None:
        for function, result, hit in index.interprocedural.all_sink_hits():
            detector = registry.get(hit.cwe)
            if detector is None:
                continue
            findings.append(
                detector.finding_from_taint(result, hit, index.source_lines, function)
            )

    for function, result in index.memory.items():
        for event in result.events:
            detector = registry.get(event.cwe)
            if detector is None:
                continue
            findings.append(
                detector.finding_from_event(event, index.source_lines, function)
            )

    return _rank(_dedupe(findings), registry)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with identical path fingerprints.

    The same defect can surface from more than one analysis path; reporting it
    twice inflates the false-positive count in evaluation and annoys users.
    """
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _rank(findings: list[Finding], registry: DetectorRegistry) -> list[Finding]:
    """Order by severity, then detector precision, then source position."""

    def sort_key(finding: Finding):
        detector = registry.get(finding.path.cwe)
        precision = _PRECISION_RANK.get(detector.precision if detector else "medium", 1)
        return (
            _SEVERITY_RANK.get(finding.severity, 3),
            precision,
            finding.path.sink.file,
            finding.path.sink.line,
        )

    return sorted(findings, key=sort_key)
