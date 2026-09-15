"""Call graph construction and bottom-up taint summaries.

Interprocedural analysis here is *summary-based* rather than inlining: each
function is analysed once, producing a description of how taint enters and
leaves it, and callers apply that description at the call site. This is what
keeps whole-project audit cost linear in the number of functions rather than
exponential in call depth.

Summaries are computed in reverse topological order of the call graph, so a
callee is always summarised before its callers. Recursive cycles -- strongly
connected components with more than one member, or self-loops -- are iterated
to fixpoint from an optimistic empty summary, with an iteration cap.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from ..ir import instructions as I
from ..ir.cfg import CFG
from .specs import RETURN, SpecTable
from .taint import TaintResult, TaintSummary, analyse, entry_seeds

#: Bound on re-analysis of a recursive component before giving up on precision.
MAX_SCC_ITERATIONS = 8


def param_key(cfg: CFG, index: int) -> str | None:
    """The taint key a parameter carries at function entry.

    Pointer, array and struct parameters keep their base name (they denote
    memory); scalars are SSA-versioned and enter at version 1.
    """
    function = cfg.function
    if index >= len(function.params):
        return None
    base = function.params[index].base
    return base if base in function.memory_vars else f"{base}.1"


class CallGraph:
    """Static call graph over the functions of one module."""

    def __init__(self, module: I.Module, cfgs: dict[str, CFG]) -> None:
        self.module = module
        self.cfgs = cfgs
        self.graph = nx.DiGraph()
        self.external_calls: dict[str, set[str]] = {}
        self.unresolved: set[str] = set()
        self._build()

    def _build(self) -> None:
        for name in self.cfgs:
            self.graph.add_node(name)
        for name, cfg in self.cfgs.items():
            for block in cfg:
                for instr in block.all_instrs:
                    if not isinstance(instr, I.Call):
                        continue
                    if instr.func in self.cfgs:
                        self.graph.add_edge(name, instr.func)
                    else:
                        self.external_calls.setdefault(name, set()).add(instr.func)

    def externals(self) -> set[str]:
        out: set[str] = set()
        for names in self.external_calls.values():
            out |= names
        return out

    def unmodelled_externals(self, specs: SpecTable) -> set[str]:
        """External calls with no specification -- the inference work list.

        This is precisely the set a specification-inference component would be
        asked to classify, and its size is a reportable metric on its own.
        """
        return {name for name in self.externals() if name not in specs}

    def reverse_topological(self) -> list[list[str]]:
        """Strongly connected components, callees before callers."""
        condensation = nx.condensation(self.graph)
        order = list(nx.topological_sort(condensation))
        groups = [sorted(condensation.nodes[n]["members"]) for n in order]
        return list(reversed(groups))

    def callers_of(self, name: str) -> list[str]:
        return list(self.graph.predecessors(name)) if name in self.graph else []

    def dump(self) -> str:
        lines = [f"callgraph  ({self.graph.number_of_nodes()} functions)"]
        for name in sorted(self.graph.nodes):
            callees = sorted(self.graph.successors(name))
            ext = sorted(self.external_calls.get(name, ()))
            lines.append(f"  {name} -> {', '.join(callees) or '-'}" + (f"   [ext: {', '.join(ext)}]" if ext else ""))
        return "\n".join(lines)


@dataclass
class InterproceduralResult:
    """Whole-program taint state: summaries plus a per-function analysis."""

    callgraph: CallGraph
    summaries: dict[str, TaintSummary] = field(default_factory=dict)
    results: dict[str, TaintResult] = field(default_factory=dict)
    iterations: int = 0

    def all_sink_hits(self):
        for name, result in self.results.items():
            for hit in result.sink_hits:
                yield name, result, hit


def summarise(
    cfg: CFG,
    specs: SpecTable,
    summaries: dict[str, TaintSummary],
    globals_: set[str] | None = None,
) -> TaintSummary:
    """Compute the taint summary of one function.

    One intraprocedural run per parameter, each seeding exactly that parameter.
    Running the parameters separately (rather than all at once) is what makes
    the resulting ``param_flows`` precise enough to be worth having: seeding all
    parameters together cannot distinguish which one reached the sink.
    """
    function = cfg.function
    globals_ = set(globals_ or set())
    summary = TaintSummary(function=function.name)

    for index in range(len(function.params)):
        seed = param_key(cfg, index)
        if seed is None:
            continue
        run = analyse(cfg, specs, summaries, seeds={seed}, globals_=globals_)
        state = run.final_state()

        targets: set = set()
        if RETURN in state:
            targets.add(RETURN)
        for other in range(len(function.params)):
            if other == index:
                continue
            other_key = param_key(cfg, other)
            if other_key is not None and other_key in state:
                targets.add(other)
        if targets:
            summary.param_flows[index] = targets

        for hit in run.sink_hits:
            summary.reaches_sink.setdefault(index, hit.cwe)
        if seed in run.analysis.sanitized:
            summary.sanitizes.add(index)

    # A function that taints its own result without any tainted input behaves
    # like a source to its callers (e.g. a wrapper around getenv).
    clean = analyse(cfg, specs, summaries, seeds=set(), globals_=globals_)
    clean_state = clean.final_state()
    summary.returns_tainted = RETURN in clean_state
    summary.taints_globals = {g for g in globals_ if g in clean_state}
    for hit in clean.sink_hits:
        if hit.key in globals_:
            summary.globals_reach_sink.setdefault(hit.key, hit.cwe)

    # A global tainted on entry may also reach a sink here; seed each global
    # that this function reads and record what it reaches.
    for name in sorted(globals_):
        if name in summary.globals_reach_sink:
            continue
        seeded = analyse(cfg, specs, summaries, seeds={name}, globals_=globals_)
        for hit in seeded.sink_hits:
            summary.globals_reach_sink.setdefault(name, hit.cwe)
            break
    return summary


def build_summaries(
    callgraph: CallGraph, specs: SpecTable, globals_: set[str] | None = None
) -> tuple[dict[str, TaintSummary], int]:
    """Bottom-up fixpoint over the call graph condensation."""
    summaries: dict[str, TaintSummary] = {}
    iterations = 0

    for component in callgraph.reverse_topological():
        recursive = len(component) > 1 or any(
            callgraph.graph.has_edge(n, n) for n in component
        )
        rounds = MAX_SCC_ITERATIONS if recursive else 1
        for _ in range(rounds):
            iterations += 1
            changed = False
            for name in component:
                cfg = callgraph.cfgs.get(name)
                if cfg is None:
                    continue
                fresh = summarise(cfg, specs, summaries, globals_)
                if summaries.get(name) != fresh:
                    summaries[name] = fresh
                    changed = True
            if not changed:
                break
    return summaries, iterations


def analyse_program(
    module: I.Module,
    cfgs: dict[str, CFG],
    specs: SpecTable,
    interprocedural: bool = True,
) -> InterproceduralResult:
    """Taint analysis over a module.

    ``interprocedural=False`` suppresses summary computation, leaving purely
    intraprocedural taint. It exists for the ablation matrix: it isolates what
    call-graph summaries contribute, which is not measurable any other way.
    """
    callgraph = CallGraph(module, cfgs)
    globals_ = set(module.globals)
    if interprocedural:
        summaries, iterations = build_summaries(callgraph, specs, globals_)
    else:
        summaries, iterations = {}, 0

    results: dict[str, TaintResult] = {}
    for name, cfg in cfgs.items():
        results[name] = analyse(
            cfg, specs, summaries, seeds=entry_seeds(cfg), globals_=globals_
        )

    return InterproceduralResult(
        callgraph=callgraph,
        summaries=summaries,
        results=results,
        iterations=iterations,
    )
