"""The generic worklist dataflow solver.

Written once and instantiated by every analysis in the project:

===========================  =========  ==================  ==================
Analysis                     Direction  Lattice             Purpose
===========================  =========  ==================  ==================
Reaching definitions         Forward    Set (union)         Validates framework
Live variables               Backward   Set (union)         Dead code, pruning
Taint propagation            Forward    Set (union)         Security detector
Allocation state machine     Forward    Map of flat states  Memory-safety CWEs
===========================  =========  ==================  ==================

The solver knows nothing about any of them. It knows about blocks, edges, a
lattice, and a transfer function -- which is the reusability claim the project
rests on, and the reason adding a new detector costs a transfer function rather
than a new engine.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Generic, TypeVar

from ..ir import instructions as I
from ..ir.cfg import CFG
from .lattice import Lattice

T = TypeVar("T")

#: Safety valve for pathological CFGs; exceeding it triggers widening.
MAX_ITERATIONS = 10_000


class Direction(Enum):
    FORWARD = "forward"
    BACKWARD = "backward"


class DataflowAnalysis(ABC, Generic[T]):
    """Base class for every analysis the solver can run."""

    direction: Direction = Direction.FORWARD

    @property
    @abstractmethod
    def lattice(self) -> Lattice[T]:
        """The domain this analysis operates over."""

    @abstractmethod
    def transfer(self, instr: I.Instr, state: T, block_label: str) -> T:
        """Effect of one instruction on the incoming state."""

    def boundary(self) -> T:
        """State at the entry (forward) or exit (backward) of the function."""
        return self.lattice.bottom()

    def transfer_phi(self, phi: I.Phi, state: T, block_label: str) -> T:
        """Effect of a phi node. Defaults to the ordinary transfer function."""
        return self.transfer(phi, state, block_label)

    def edge_transfer(self, pred: str, succ: str, state: T) -> T:
        """Effect of traversing the CFG edge ``pred -> succ``.

        Applied to the state as it crosses an edge, before the join. Two
        analyses need it and neither can be expressed without it:

        * live variables -- a phi operand is live on the edge it arrives from,
          not at the head of the block containing the phi;
        * taint propagation -- a guard such as ``if (n < sizeof buf)`` removes
          taint only on the edge into its true branch.

        The default is the identity, so analyses that do not care ignore it.
        """
        return state

    def initial(self, block_label: str) -> T:
        return self.lattice.bottom()


@dataclass
class DataflowResult(Generic[T]):
    """Per-block states plus the instruction-level trace analyses need."""

    analysis: DataflowAnalysis[T]
    cfg: CFG
    in_state: dict[str, T] = field(default_factory=dict)
    out_state: dict[str, T] = field(default_factory=dict)
    iterations: int = 0
    widened: bool = False

    def state_before(self, target: I.Instr) -> T | None:
        """Recompute the state immediately before ``target``.

        Recomputing rather than caching every instruction keeps peak memory
        proportional to the number of blocks, which matters on large inputs.
        """
        analysis = self.analysis
        for block in self.cfg:
            instrs = block.all_instrs
            if analysis.direction is Direction.BACKWARD:
                state = self.out_state.get(block.label, analysis.lattice.bottom())
                sequence = list(reversed(instrs))
            else:
                state = self.in_state.get(block.label, analysis.lattice.bottom())
                sequence = instrs
            for instr in sequence:
                if instr is target:
                    return state
                state = _apply(analysis, instr, state, block.label)
        return None

    def at_block_entry(self, label: str) -> T:
        return self.in_state.get(label, self.analysis.lattice.bottom())

    def at_block_exit(self, label: str) -> T:
        return self.out_state.get(label, self.analysis.lattice.bottom())


def _apply(analysis: DataflowAnalysis[T], instr: I.Instr, state: T, label: str) -> T:
    if isinstance(instr, I.Phi):
        return analysis.transfer_phi(instr, state, label)
    return analysis.transfer(instr, state, label)


def solve(cfg: CFG, analysis: DataflowAnalysis[T]) -> DataflowResult[T]:
    """Run ``analysis`` over ``cfg`` to fixpoint.

    A worklist algorithm: a block is re-examined only when one of its inputs
    changed. Convergence is guaranteed for monotone transfer functions over a
    finite lattice; ``MAX_ITERATIONS`` plus ``Lattice.widen`` bounds the
    pathological cases (deep recursion, very wide CFGs) rather than hanging.
    """
    lattice = analysis.lattice
    backward = analysis.direction is Direction.BACKWARD

    in_state: dict[str, T] = {b.label: analysis.initial(b.label) for b in cfg}
    out_state: dict[str, T] = {b.label: analysis.initial(b.label) for b in cfg}

    boundary_label = cfg.exit if backward else cfg.entry
    if backward:
        out_state[boundary_label] = analysis.boundary()
    else:
        in_state[boundary_label] = analysis.boundary()

    worklist: deque[str] = deque(b.label for b in cfg)
    queued = {b.label for b in cfg}
    iterations = 0
    widened = False

    while worklist:
        label = worklist.popleft()
        queued.discard(label)
        iterations += 1
        if iterations > MAX_ITERATIONS:  # pragma: no cover - safety valve
            widened = True
            break

        block = cfg.blocks.get(label)
        if block is None:
            continue

        if backward:
            incoming = (
                analysis.boundary()
                if label == boundary_label
                else lattice.join_all(
                    analysis.edge_transfer(label, s, in_state.get(s, lattice.bottom()))
                    for s in cfg.succs(label)
                )
            )
            out_state[label] = incoming
            state = incoming
            for instr in reversed(block.all_instrs):
                state = _apply(analysis, instr, state, label)
            changed = state != in_state.get(label)
            if changed:
                in_state[label] = state
                neighbours = cfg.preds(label)
        else:
            incoming = (
                analysis.boundary()
                if label == boundary_label
                else lattice.join_all(
                    analysis.edge_transfer(p, label, out_state.get(p, lattice.bottom()))
                    for p in cfg.preds(label)
                )
            )
            in_state[label] = incoming
            state = incoming
            for instr in block.all_instrs:
                state = _apply(analysis, instr, state, label)
            changed = state != out_state.get(label)
            if changed:
                out_state[label] = state
                neighbours = cfg.succs(label)

        if changed:
            for n in neighbours:
                if n not in queued and n in cfg.blocks:
                    worklist.append(n)
                    queued.add(n)

    return DataflowResult(
        analysis=analysis,
        cfg=cfg,
        in_state=in_state,
        out_state=out_state,
        iterations=iterations,
        widened=widened,
    )
