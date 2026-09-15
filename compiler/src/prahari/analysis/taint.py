"""Taint propagation -- the security analysis, as a third instantiation of the
generic dataflow framework.

Two things distinguish this from the classical analyses:

1. **It builds a provenance graph while it solves.** Knowing *that* a value is
   tainted is not enough to report anything useful; a finding needs the route
   from source to sink. Every propagation adds an edge to a taint-flow graph,
   and a shortest path over that graph is the trace shown to the user. This is
   also what makes the slice handed to an adjudicator small: the path, not the
   file.

2. **Taint is keyed on SSA definitions where possible.** For a renameable
   scalar the key is the versioned name, so a tainted value and a later safe
   value of the same variable never merge. For arrays, structs and address-taken
   variables the key is the base name -- a field-insensitive memory model, which
   is the documented scope boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from ..diagnostics import Guard, Location
from ..ir import instructions as I
from ..ir.cfg import CFG
from .framework import DataflowAnalysis, Direction, solve
from .lattice import Lattice, SetLattice
from .specs import RETURN, Position, SpecTable


@dataclass
class TaintSummary:
    """The effect of one user-defined function on taint, computed bottom-up.

    Produced by running the intraprocedural analysis once per parameter with
    that parameter seeded. Cheap because the analysed functions are small, and
    far easier to justify in a report than a symbolic multi-label lattice.
    """

    function: str
    param_flows: dict[int, set[Position]] = field(default_factory=dict)
    reaches_sink: dict[int, str] = field(default_factory=dict)
    sanitizes: set[int] = field(default_factory=set)
    returns_tainted: bool = False
    #: File-scope variables this function leaves tainted. Globals are shared
    #: storage with no parameter position, so a purely parameter-based summary
    #: cannot express "this call taints g_buf" -- and a source laundered
    #: through a global is a routine way for a flow to escape detection.
    taints_globals: set[str] = field(default_factory=set)
    #: Globals whose taint this function carries to a sink, by CWE.
    globals_reach_sink: dict[str, str] = field(default_factory=dict)

    def targets_for(self, position: int) -> list[Position]:
        return sorted(self.param_flows.get(position, set()), key=str)

    def describe(self) -> str:
        """One-line human summary, used in path traces and prompt slices."""
        if not self.param_flows and not self.reaches_sink:
            return f"{self.function}: no taint flow"
        parts = []
        for src, targets in sorted(self.param_flows.items()):
            for dst in sorted(targets, key=str):
                label = "return" if dst == RETURN else f"param{dst}"
                parts.append(f"param{src} -> {label}")
        for src, cwe in sorted(self.reaches_sink.items()):
            parts.append(f"param{src} -> {cwe} sink")
        for name in sorted(self.taints_globals):
            parts.append(f"taints global {name}")
        for name, cwe in sorted(self.globals_reach_sink.items()):
            parts.append(f"global {name} -> {cwe} sink")
        sanitised = ", ".join(f"param{p}" for p in sorted(self.sanitizes))
        text = f"{self.function}: " + "; ".join(parts)
        return text + (f"; sanitises {sanitised}" if sanitised else "; no sanitisation")


@dataclass
class SinkHit:
    """A tainted value observed arriving at a security-sensitive position."""

    instr: I.Call
    argument_index: int
    cwe: str
    key: str
    block: str
    spec_origin: str = "builtin"
    note: str = ""

    @property
    def location(self) -> Location:
        return self.instr.loc


class TaintAnalysis(DataflowAnalysis[frozenset]):
    """Forward, union-joined propagation of tainted values."""

    direction = Direction.FORWARD

    def __init__(
        self,
        cfg: CFG,
        specs: SpecTable,
        summaries: dict[str, TaintSummary] | None = None,
        seeds: set[str] | None = None,
        globals_: set[str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.specs = specs
        self.summaries = summaries or {}
        self.seeds = frozenset(seeds or set())
        self.globals = set(globals_ or set())
        self.memory = set(cfg.function.memory_vars) | self.globals
        self._lattice = SetLattice()

        self.graph = nx.DiGraph()
        self.source_sites: dict[str, I.Instr] = {}
        self.sanitized: set[str] = set()

    @property
    def lattice(self) -> Lattice[frozenset]:
        return self._lattice

    def boundary(self) -> frozenset:
        entry_loc = self.cfg.function.loc or self.cfg.blocks[self.cfg.entry].loc
        for seed in self.seeds:
            self.graph.add_node(seed, source=True, label="parameter is attacker-controlled")
            self.source_sites.setdefault(seed, I.Label(name=seed, loc=entry_loc))
        return self.seeds

    # -- key handling -------------------------------------------------------

    def key(self, operand: I.Operand | None) -> str | None:
        """The taint identity of an operand, or None for literals."""
        if isinstance(operand, I.Name):
            return operand.base if operand.base in self.memory else str(operand)
        return None

    def _tainted(self, operand: I.Operand | None, state: frozenset) -> bool:
        k = self.key(operand)
        return k is not None and k in state

    def _flow(self, src_key: str, dst_key: str, instr: I.Instr, label: str) -> None:
        """Record a propagation edge for later path reconstruction."""
        if src_key == dst_key:
            return
        self.graph.add_edge(src_key, dst_key, instr=instr, label=label)

    def _introduce(self, dst_key: str, instr: I.Instr, label: str) -> None:
        self.graph.add_node(dst_key)
        self.source_sites.setdefault(dst_key, instr)
        self.graph.nodes[dst_key]["source"] = True
        self.graph.nodes[dst_key]["label"] = label

    # -- transfer functions -------------------------------------------------

    def transfer(self, instr: I.Instr, state: frozenset, block_label: str) -> frozenset:
        handler = getattr(self, f"_t_{type(instr).__name__}", None)
        return handler(instr, state) if handler is not None else state

    def transfer_phi(self, phi: I.Phi, state: frozenset, block_label: str) -> frozenset:
        dst = self.key(phi.dst)
        if dst is None:
            return state
        for operand, _ in phi.incoming:
            if self._tainted(operand, state):
                self._flow(self.key(operand), dst, phi, "merged at control-flow join")
                return state | {dst}
        return state - {dst}

    def _t_Assign(self, instr: I.Assign, state: frozenset) -> frozenset:
        dst = self.key(instr.dst)
        if dst is None:
            return state
        if self._tainted(instr.src, state):
            self._flow(self.key(instr.src), dst, instr, "copied")
            return state | {dst}
        return state - {dst}

    def _t_BinOp(self, instr: I.BinOp, state: frozenset) -> frozenset:
        dst = self.key(instr.dst)
        if dst is None:
            return state
        tainted = [o for o in (instr.lhs, instr.rhs) if self._tainted(o, state)]
        if tainted:
            for o in tainted:
                self._flow(self.key(o), dst, instr, f"combined with {instr.op}")
            return state | {dst}
        return state - {dst}

    def _t_UnOp(self, instr: I.UnOp, state: frozenset) -> frozenset:
        dst = self.key(instr.dst)
        if dst is None:
            return state
        if self._tainted(instr.src, state):
            self._flow(self.key(instr.src), dst, instr, f"applied {instr.op}")
            return state | {dst}
        return state - {dst}

    def _t_Load(self, instr: I.Load, state: frozenset) -> frozenset:
        """A read from tainted storage, or at a tainted offset, yields taint."""
        dst = self.key(instr.dst)
        if dst is None:
            return state
        for operand, why in ((instr.ptr, "read from tainted storage"),
                             (instr.index, "read at attacker-controlled index")):
            if self._tainted(operand, state):
                self._flow(self.key(operand), dst, instr, why)
                return state | {dst}
        return state - {dst}

    def _t_Store(self, instr: I.Store, state: frozenset) -> frozenset:
        """A write into storage taints that storage, field-insensitively."""
        dst = self.key(instr.ptr)
        if dst is None:
            return state
        if self._tainted(instr.src, state):
            self._flow(self.key(instr.src), dst, instr, "written into buffer")
            return state | {dst}
        return state  # no strong update: other fields may still be tainted

    def _t_AddrOf(self, instr: I.AddrOf, state: frozenset) -> frozenset:
        dst = self.key(instr.dst)
        if dst is None:
            return state
        if self._tainted(instr.src, state):
            self._flow(self.key(instr.src), dst, instr, "address taken")
            return state | {dst}
        return state - {dst}

    def _t_Ret(self, instr: I.Ret, state: frozenset) -> frozenset:
        if self._tainted(instr.src, state):
            self._flow(self.key(instr.src), RETURN, instr, "returned to caller")
            return state | {RETURN}
        return state

    def _t_Call(self, instr: I.Call, state: frozenset) -> frozenset:
        spec = self.specs.get(instr.func)
        summary = self.summaries.get(instr.func)
        new = set(state)

        dst_key = self.key(instr.dst)
        if dst_key is not None:
            new.discard(dst_key)

        def position_key(position: Position) -> str | None:
            if position == RETURN:
                return dst_key
            if isinstance(position, int) and position < len(instr.args):
                return self.key(instr.args[position])
            return None

        if spec is not None:
            for position in spec.sanitizes:
                k = position_key(position)
                if k is not None:
                    new.discard(k)
                    self.sanitized.add(k)
            for position in spec.taints:
                k = position_key(position)
                if k is not None:
                    self._introduce(k, instr, spec.note or f"{instr.func}() introduces untrusted data")
                    new.add(k)
            self._apply_flows(instr, state, new, spec.targets_for, position_key)

        if summary is not None:
            for index in range(len(instr.args)):
                if index in summary.sanitizes:
                    k = position_key(index)
                    if k is not None:
                        new.discard(k)
            self._apply_flows(
                instr, state, new, summary.targets_for, position_key, label=summary.describe()
            )
            for name in summary.taints_globals:
                self._introduce(name, instr, f"{instr.func}() writes untrusted data into {name}")
                new.add(name)
            if summary.returns_tainted and dst_key is not None:
                self._introduce(dst_key, instr, f"{instr.func}() returns untrusted data")
                new.add(dst_key)

        if spec is None and summary is None and dst_key is not None:
            # Unknown external function: conservatively propagate argument taint
            # into the result. Recorded so the report can quantify how often the
            # analysis had to guess.
            for arg in instr.args:
                if self._tainted(arg, state):
                    self._flow(self.key(arg), dst_key, instr, f"through unmodelled {instr.func}()")
                    new.add(dst_key)
                    break

        return frozenset(new)

    def _apply_flows(self, instr, state, new, targets_for, position_key, label: str = "") -> None:
        for index, arg in enumerate(instr.args):
            if not self._tainted(arg, state):
                continue
            src_key = self.key(arg)
            for target in targets_for(index):
                target_key = position_key(target)
                if target_key is None:
                    continue
                why = label or f"propagated by {instr.func}()"
                self._flow(src_key, target_key, instr, why)
                new.add(target_key)

    # -- results ------------------------------------------------------------

    def collect_sinks(self, result) -> list[SinkHit]:
        """Walk the solved states and record every tainted value at a sink."""
        hits: list[SinkHit] = []
        for block in self.cfg:
            state = result.at_block_entry(block.label)
            for instr in block.all_instrs:
                if isinstance(instr, I.Call):
                    hits.extend(self._sinks_at(instr, state, block.label))
                state = (
                    self.transfer_phi(instr, state, block.label)
                    if isinstance(instr, I.Phi)
                    else self.transfer(instr, state, block.label)
                )
        return hits

    def _sinks_at(self, instr: I.Call, state: frozenset, block: str) -> list[SinkHit]:
        spec = self.specs.get(instr.func)
        summary = self.summaries.get(instr.func)
        hits: list[SinkHit] = []

        if spec is not None:
            for index, cwe in spec.sinks:
                if index < len(instr.args) and self._tainted(instr.args[index], state):
                    hits.append(
                        SinkHit(
                            instr=instr,
                            argument_index=index,
                            cwe=cwe,
                            key=self.key(instr.args[index]),
                            block=block,
                            spec_origin=spec.origin,
                            note=spec.note,
                        )
                    )
        if summary is not None:
            for name, cwe in summary.globals_reach_sink.items():
                if name in state:
                    hits.append(
                        SinkHit(
                            instr=instr,
                            argument_index=-1,
                            cwe=cwe,
                            key=name,
                            block=block,
                            note=f"global {name} reaches a sink inside {instr.func}()",
                        )
                    )
            for index, cwe in summary.reaches_sink.items():
                if index < len(instr.args) and self._tainted(instr.args[index], state):
                    hits.append(
                        SinkHit(
                            instr=instr,
                            argument_index=index,
                            cwe=cwe,
                            key=self.key(instr.args[index]),
                            block=block,
                            note=f"via {summary.describe()}",
                        )
                    )
        return hits

    def guards_dominating(self, block_label: str) -> list[Guard]:
        """Conditions that must hold for control to reach ``block_label``.

        Reported alongside a finding so a reviewer -- or an adjudicator -- can
        see what validation, if any, already stands between source and sink.
        """
        guards: list[Guard] = []
        for label, block in self.cfg.blocks.items():
            if label == block_label or not self.cfg.dominates(label, block_label):
                continue
            term = block.terminator
            if isinstance(term, I.CBranch):
                guards.append(Guard(location=term.loc, condition=str(term.cond)))
        return guards


@dataclass
class TaintResult:
    """Everything the detectors need from one function's taint analysis."""

    function: str
    analysis: TaintAnalysis
    result: object
    sink_hits: list[SinkHit]

    @property
    def graph(self) -> nx.DiGraph:
        return self.analysis.graph

    def final_state(self) -> frozenset:
        return self.result.at_block_entry(self.analysis.cfg.exit)

    def path_to(self, hit: SinkHit) -> list[tuple[str, I.Instr | None, str]]:
        """Shortest source-to-sink route through the taint-flow graph.

        Returns ``(key, instruction, explanation)`` triples. The first entry is
        the source; the instruction is the one that produced that step.
        """
        graph = self.graph
        if hit.key not in graph:
            return []
        sources = [n for n, d in graph.nodes(data=True) if d.get("source")]
        best: list[str] | None = None
        for source in sources:
            if source == hit.key:
                best = [source]
                break
            try:
                candidate = nx.shortest_path(graph, source, hit.key)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if best is None or len(candidate) < len(best):
                best = candidate
        if best is None:
            return []

        steps: list[tuple[str, I.Instr | None, str]] = []
        origin = graph.nodes[best[0]]
        steps.append(
            (best[0], self.analysis.source_sites.get(best[0]), origin.get("label", "untrusted input"))
        )
        for a, b in zip(best, best[1:]):
            data = graph.get_edge_data(a, b) or {}
            steps.append((b, data.get("instr"), data.get("label", "propagated")))
        return steps


def analyse(
    cfg: CFG,
    specs: SpecTable,
    summaries: dict[str, TaintSummary] | None = None,
    seeds: set[str] | None = None,
    globals_: set[str] | None = None,
) -> TaintResult:
    """Run intraprocedural taint analysis over one function."""
    analysis = TaintAnalysis(cfg, specs, summaries, seeds, globals_)
    result = solve(cfg, analysis)
    return TaintResult(
        function=cfg.name,
        analysis=analysis,
        result=result,
        sink_hits=analysis.collect_sinks(result),
    )


def entry_seeds(cfg: CFG) -> set[str]:
    """Taint seeds implied by a function signature.

    ``main``'s ``argv`` is attacker-controlled by definition; this is the one
    source that needs no library call to introduce it.
    """
    seeds: set[str] = set()
    function = cfg.function
    if function.name == "main":
        for param, type_name in zip(function.params, function.param_types):
            if "*" in type_name or "[" in type_name:
                seeds.add(param.base)
    return seeds
