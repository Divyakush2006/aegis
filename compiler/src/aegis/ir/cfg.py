"""Control flow graph construction, dominator tree and dominance frontiers.

The graph itself is a ``networkx.DiGraph`` so that standard graph algorithms
are available, but the dominance frontier computation is implemented here
directly (Cooper, Harvey & Kennedy) because it is the input to SSA phi
placement and the correctness of phi placement is a project deliverable.
``tests/test_cfg.py`` cross-checks it against networkx on every test program.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from ..diagnostics import Location
from . import instructions as I

ENTRY = "entry"
EXIT = "$exit"


@dataclass
class BasicBlock:
    """A maximal straight-line instruction sequence."""

    label: str
    instrs: list[I.Instr] = field(default_factory=list)
    phis: list[I.Phi] = field(default_factory=list)

    @property
    def terminator(self) -> I.Instr | None:
        return self.instrs[-1] if self.instrs and self.instrs[-1].is_terminator else None

    @property
    def all_instrs(self) -> list[I.Instr]:
        """Phi nodes first, matching their semantics at block entry."""
        return [*self.phis, *self.instrs]

    @property
    def loc(self) -> Location:
        for ins in self.instrs:
            if ins.loc.line:
                return ins.loc
        return Location()

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<Block {self.label} ({len(self.instrs)} instrs)>"


class CFG:
    """Control flow graph for a single function."""

    def __init__(self, function: I.Function) -> None:
        self.function = function
        self.name = function.name
        self.blocks: dict[str, BasicBlock] = {}
        self.graph = nx.DiGraph()
        self._build(function)
        self._prune_unreachable()
        self._idom: dict[str, str] | None = None
        self._frontiers: dict[str, set[str]] | None = None

    # -- construction -------------------------------------------------------

    def _build(self, function: I.Function) -> None:
        current: BasicBlock | None = None
        order: list[str] = []
        fallthroughs: list[tuple[str, str]] = []

        for instr in function.body:
            if isinstance(instr, I.Label):
                if current is not None and current.terminator is None:
                    fallthroughs.append((current.label, instr.name))
                current = BasicBlock(label=instr.name)
                self.blocks[instr.name] = current
                order.append(instr.name)
                continue
            if current is None:  # instructions before any label
                current = BasicBlock(label=ENTRY)
                self.blocks[ENTRY] = current
                order.append(ENTRY)
            if current.terminator is not None:
                # Unreachable code after a terminator: start a synthetic block.
                label = f"$dead{len(order)}"
                current = BasicBlock(label=label)
                self.blocks[label] = current
                order.append(label)
            current.instrs.append(instr)

        self.blocks.setdefault(EXIT, BasicBlock(label=EXIT))
        if EXIT not in order:
            order.append(EXIT)
        self.order = order

        for label in order:
            self.graph.add_node(label)
        for src, dst in fallthroughs:
            self.graph.add_edge(src, dst)

        for label, block in self.blocks.items():
            term = block.terminator
            if isinstance(term, I.Jump):
                self.graph.add_edge(label, term.target)
            elif isinstance(term, I.CBranch):
                self.graph.add_edge(label, term.then_label)
                self.graph.add_edge(label, term.else_label)
            elif isinstance(term, I.Ret):
                self.graph.add_edge(label, EXIT)
            elif term is None and label != EXIT and not block.instrs:
                pass

    def _prune_unreachable(self) -> None:
        """Drop blocks unreachable from entry; dominator algorithms require it."""
        if ENTRY not in self.graph:
            self.graph.add_node(ENTRY)
        reachable = nx.descendants(self.graph, ENTRY) | {ENTRY}
        reachable.add(EXIT)
        for label in list(self.blocks):
            if label not in reachable:
                del self.blocks[label]
                if label in self.graph:
                    self.graph.remove_node(label)
        self.order = [b for b in self.order if b in self.blocks]

    # -- graph accessors ----------------------------------------------------

    @property
    def entry(self) -> str:
        return ENTRY

    @property
    def exit(self) -> str:
        return EXIT

    def preds(self, label: str) -> list[str]:
        return list(self.graph.predecessors(label))

    def succs(self, label: str) -> list[str]:
        return list(self.graph.successors(label))

    def block(self, label: str) -> BasicBlock:
        return self.blocks[label]

    def __iter__(self):
        return iter(self.blocks.values())

    def __len__(self) -> int:
        return len(self.blocks)

    # -- dominance ----------------------------------------------------------

    @property
    def idom(self) -> dict[str, str]:
        """Immediate dominator of each block (entry maps to itself)."""
        if self._idom is None:
            self._idom = nx.immediate_dominators(self.graph, ENTRY)
        return self._idom

    def dominator_tree(self) -> nx.DiGraph:
        tree = nx.DiGraph()
        for node, parent in self.idom.items():
            tree.add_node(node)
            if node != parent:
                tree.add_edge(parent, node)
        return tree

    def dominates(self, a: str, b: str) -> bool:
        """True if every path from entry to ``b`` passes through ``a``."""
        node = b
        while True:
            if node == a:
                return True
            parent = self.idom.get(node, node)
            if parent == node:
                return False
            node = parent

    @property
    def dominance_frontiers(self) -> dict[str, set[str]]:
        """Cooper-Harvey-Kennedy dominance frontiers.

        For each join point ``b`` and each predecessor ``p``, walk ``p`` up the
        dominator tree until the immediate dominator of ``b`` is reached, adding
        ``b`` to the frontier of every block on the way.
        """
        if self._frontiers is not None:
            return self._frontiers

        idom = self.idom
        df: dict[str, set[str]] = {b: set() for b in self.blocks}
        for b in self.blocks:
            preds = self.preds(b)
            if len(preds) < 2:
                continue
            for p in preds:
                runner = p
                while runner != idom.get(b, b) and runner in idom:
                    df[runner].add(b)
                    parent = idom[runner]
                    if parent == runner:
                        break
                    runner = parent
        self._frontiers = df
        return df

    # -- display ------------------------------------------------------------

    def dump(self) -> str:
        lines = [f"cfg {self.name}  ({len(self.blocks)} blocks)"]
        for label in self.order:
            block = self.blocks.get(label)
            if block is None:
                continue
            preds = ", ".join(self.preds(label)) or "-"
            succs = ", ".join(self.succs(label)) or "-"
            lines.append(f"  {label}:  preds[{preds}]  succs[{succs}]")
            for ins in block.all_instrs:
                lines.append(f"      {ins}")
        return "\n".join(lines)

    def to_dot(self) -> str:  # pragma: no cover - visualisation helper
        rows = ["digraph cfg {", '  node [shape=box fontname="monospace"];']
        for label, block in self.blocks.items():
            body = "\\l".join(str(i) for i in block.all_instrs)
            rows.append(f'  "{label}" [label="{label}:\\l{body}\\l"];')
        for a, b in self.graph.edges():
            rows.append(f'  "{a}" -> "{b}";')
        rows.append("}")
        return "\n".join(rows)


def build_cfgs(module: I.Module) -> dict[str, CFG]:
    return {name: CFG(fn) for name, fn in module.functions.items()}
