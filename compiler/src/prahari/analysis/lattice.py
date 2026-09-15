"""Lattice definitions for the dataflow framework.

A lattice supplies the *domain* of an analysis and how information from
converging control flow paths is combined. Keeping it separate from the solver
is what lets one solver serve reaching definitions, live variables, taint
propagation and the allocation state machine without modification.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, Iterable, TypeVar

T = TypeVar("T")


class Lattice(ABC, Generic[T]):
    """The algebraic structure a dataflow analysis operates over."""

    @abstractmethod
    def bottom(self) -> T:
        """The least element -- the initial value for every block."""

    @abstractmethod
    def join(self, a: T, b: T) -> T:
        """The meet/join operator applied where control flow converges."""

    @abstractmethod
    def leq(self, a: T, b: T) -> bool:
        """Partial order; ``solve`` uses it only for assertions and widening."""

    def join_all(self, values: Iterable[T]) -> T:
        result = self.bottom()
        for value in values:
            result = self.join(result, value)
        return result

    def widen(self, old: T, new: T) -> T:
        """Accelerate convergence. The default is exact (no widening)."""
        return new


class SetLattice(Lattice[frozenset]):
    """Powerset lattice ordered by inclusion, joined by union.

    Used by reaching definitions, live variables and taint propagation. The
    "may" direction (union) is the right choice for a security analysis: a value
    is treated as tainted if it is tainted on *any* incoming path.
    """

    def bottom(self) -> frozenset:
        return frozenset()

    def join(self, a: frozenset, b: frozenset) -> frozenset:
        return a | b

    def leq(self, a: frozenset, b: frozenset) -> bool:
        return a <= b


class IntersectionLattice(Lattice[frozenset]):
    """Powerset lattice joined by intersection, for "must" analyses.

    ``bottom`` is represented by ``None`` (the universal set) because the true
    top element is not enumerable before the analysis runs.
    """

    def bottom(self):
        return None

    def join(self, a, b):
        if a is None:
            return b
        if b is None:
            return a
        return a & b

    def leq(self, a, b) -> bool:
        if b is None:
            return True
        if a is None:
            return False
        return a >= b


class MapLattice(Lattice[dict]):
    """Pointwise lifting of a value lattice over a set of keys.

    The allocation state machine (``UNALLOCATED -> ALLOCATED -> FREED``) uses
    this: each pointer maps to its own state, joined pointwise.
    """

    def __init__(self, value_lattice: Lattice) -> None:
        self.value_lattice = value_lattice

    def bottom(self) -> dict:
        return {}

    def join(self, a: dict, b: dict) -> dict:
        out = dict(a)
        for key, value in b.items():
            out[key] = self.value_lattice.join(out[key], value) if key in out else value
        return out

    def leq(self, a: dict, b: dict) -> bool:
        return all(key in b and self.value_lattice.leq(value, b[key]) for key, value in a.items())


class FlatLattice(Lattice):
    """A flat lattice over an explicit ordering of states.

    ``order`` lists states from least to greatest; the join of two distinct
    states is the greater one, which models monotone state escalation such as
    ``ALLOCATED`` joined with ``FREED`` becoming ``FREED``.
    """

    def __init__(self, order: list, error_state=None) -> None:
        self.order = list(order)
        self.rank = {state: i for i, state in enumerate(self.order)}
        self.error_state = error_state

    def bottom(self):
        return self.order[0]

    def join(self, a, b):
        if a == b:
            return a
        if self.error_state is not None and self.error_state in (a, b):
            return self.error_state
        return a if self.rank.get(a, 0) >= self.rank.get(b, 0) else b

    def leq(self, a, b) -> bool:
        return self.rank.get(a, 0) <= self.rank.get(b, 0)
