"""Live variables -- backward, union.

The second instantiation of the generic framework, and the one that proves the
solver is genuinely direction-agnostic: nothing changes but ``direction`` and
the transfer function.

Its result drives the dead-store diagnostic, and is the classical input to
register allocation and to pruned-SSA phi placement.
"""
from __future__ import annotations

from ..ir import instructions as I
from ..ir.cfg import CFG
from .framework import DataflowAnalysis, DataflowResult, Direction, solve
from .lattice import Lattice, SetLattice


class LiveVariables(DataflowAnalysis[frozenset]):
    """``in[n] = use[n] | (out[n] - def[n])``"""

    direction = Direction.BACKWARD

    def __init__(self, cfg: CFG) -> None:
        self.cfg = cfg
        self._lattice = SetLattice()

    @property
    def lattice(self) -> Lattice[frozenset]:
        return self._lattice

    def boundary(self) -> frozenset:
        return frozenset()

    def transfer(self, instr: I.Instr, state: frozenset, block_label: str) -> frozenset:
        defined = {str(d) for d in instr.defs}
        used = {str(u) for u in instr.uses}
        return (state - defined) | used

    def transfer_phi(self, phi: I.Phi, state: frozenset, block_label: str) -> frozenset:
        """A phi kills its result but reads nothing at the head of this block.

        Its operands become live on the individual incoming edges instead; see
        :meth:`edge_transfer`. Treating them as live here would wrongly extend
        every operand's live range across *all* incoming edges.
        """
        return state - {str(phi.dst)}

    def edge_transfer(self, pred: str, succ: str, state: frozenset) -> frozenset:
        """Add the phi operands of ``succ`` that arrive along the ``pred`` edge."""
        block = self.cfg.blocks.get(succ)
        if block is None or not block.phis:
            return state
        arriving = {
            str(operand)
            for phi in block.phis
            for operand, origin in phi.incoming
            if origin == pred
        }
        return state | arriving


def run(cfg: CFG) -> DataflowResult[frozenset]:
    return solve(cfg, LiveVariables(cfg))


def dead_stores(cfg: CFG, result: DataflowResult[frozenset] | None = None) -> list[I.Instr]:
    """Definitions whose value is not live afterwards.

    Reported as a hint by the editor and used as the dead-code signal the
    project documents list under the development-assistant features.
    """
    result = result or run(cfg)
    dead: list[I.Instr] = []
    for block in cfg:
        state = result.at_block_exit(block.label)
        for instr in reversed(block.all_instrs):
            live_after = state
            state = result.analysis.transfer(instr, state, block.label)
            if isinstance(instr, (I.Call, I.Store, I.Ret, I.Jump, I.CBranch, I.Label)):
                continue  # side effects, or not a definition
            for d in instr.defs:
                if str(d) not in live_after and not d.base.startswith("%t"):
                    dead.append(instr)
                    break
    return dead
