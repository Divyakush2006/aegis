"""Reaching definitions -- forward, union, with kill sets.

The first instantiation of the generic framework. It exists to validate the
solver against a textbook analysis with a known answer before that same solver
is trusted with taint propagation.

It deliberately runs over *base* variable names rather than SSA names. Under
SSA every definition is unique and no definition ever kills another, which
would make the kill set trivially empty and the analysis a weaker test of the
framework. Running on base names exercises gen/kill properly.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..diagnostics import Location
from ..ir import instructions as I
from ..ir.cfg import CFG
from .framework import DataflowAnalysis, DataflowResult, Direction, solve
from .lattice import Lattice, SetLattice


@dataclass(frozen=True)
class Definition:
    """One assignment site, identified independently of SSA versioning."""

    variable: str
    index: int
    location: Location

    def __str__(self) -> str:
        return f"{self.variable}@{self.location.line}#{self.index}"


class ReachingDefinitions(DataflowAnalysis[frozenset]):
    """``out[n] = gen[n] | (in[n] - kill[n])``"""

    direction = Direction.FORWARD

    def __init__(self, cfg: CFG) -> None:
        self.cfg = cfg
        self._lattice = SetLattice()
        self.definitions: dict[int, Definition] = {}
        self.by_variable: dict[str, set[Definition]] = {}
        self._index(cfg)

    @property
    def lattice(self) -> Lattice[frozenset]:
        return self._lattice

    def _index(self, cfg: CFG) -> None:
        counter = 0
        for block in cfg:
            for instr in block.all_instrs:
                for d in instr.defs:
                    counter += 1
                    definition = Definition(d.base, counter, instr.loc)
                    self.definitions[id(instr)] = definition
                    self.by_variable.setdefault(d.base, set()).add(definition)
                if isinstance(instr, I.Store):
                    counter += 1
                    definition = Definition(instr.ptr.base, counter, instr.loc)
                    self.definitions[id(instr)] = definition
                    self.by_variable.setdefault(instr.ptr.base, set()).add(definition)

    def boundary(self) -> frozenset:
        return frozenset()

    def transfer(self, instr: I.Instr, state: frozenset, block_label: str) -> frozenset:
        definition = self.definitions.get(id(instr))
        if definition is None:
            return state
        killed = self.by_variable.get(definition.variable, set()) - {definition}
        return (state - killed) | {definition}


def run(cfg: CFG) -> DataflowResult[frozenset]:
    return solve(cfg, ReachingDefinitions(cfg))
