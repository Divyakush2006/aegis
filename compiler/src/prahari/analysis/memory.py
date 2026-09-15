"""Heap state machine -- the fourth instantiation of the dataflow framework.

Three of the six CWE classes are not taint problems at all: they are questions
about the *state of an allocation* at a program point. They are implemented
here with the same generic solver and a different lattice:

    UNALLOCATED -> ALLOCATED -> CHECKED -> FREED -> ERROR

``MapLattice(FlatLattice(...))`` gives one state per allocation, joined
pointwise, so an allocation freed on one path and live on another joins to
``FREED``. That the security detectors and the classical analyses share a
solver is the reusability claim of the project; this module tests it hardest,
because nothing in the solver was written with heap state in mind.

**Allocations are keyed by allocation site, not by variable name.** ``p = q =
malloc(n)`` is one allocation with two names, and freeing either must mark the
allocation freed. Keying on names instead double-counts every copy -- the most
common way a naive leak checker generates false positives.

Scope: field-insensitive, no points-to analysis. The model reasons about
allocations reachable through directly-named pointers. Aliasing through struct
fields or arrays of pointers is outside the analysed subset and is reported as
a documented limitation rather than silently mishandled.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..diagnostics import Location
from ..ir import instructions as I
from ..ir.cfg import CFG
from .framework import DataflowAnalysis, DataflowResult, Direction, solve
from .lattice import FlatLattice, Lattice, MapLattice

UNALLOCATED = "UNALLOCATED"
ALLOCATED = "ALLOCATED"
CHECKED = "CHECKED"
FREED = "FREED"
ERROR = "ERROR"

#: Ordered least to greatest; the join of two states is the greater one.
STATE_ORDER = [UNALLOCATED, ALLOCATED, CHECKED, FREED, ERROR]
LIVE_STATES = {ALLOCATED, CHECKED}

ALLOCATORS = {"malloc", "calloc", "realloc", "strdup"}
DEALLOCATORS = {"free"}


@dataclass
class MemoryEvent:
    """A heap-safety violation observed at a program point."""

    cwe: str
    key: str
    location: Location
    allocation: Location
    detail: str


class HeapStateAnalysis(DataflowAnalysis[dict]):
    """Tracks the state of each allocation across the control flow graph."""

    direction = Direction.FORWARD

    def __init__(self, cfg: CFG) -> None:
        self.cfg = cfg
        self.memory = set(cfg.function.memory_vars)
        self._lattice = MapLattice(FlatLattice(STATE_ORDER, error_state=ERROR))
        #: name -> allocation id. Flow-insensitive: within the analysed subset a
        #: name denotes at most one allocation site per function.
        self.alias: dict[str, str] = {}
        self.sites: dict[str, Location] = {}
        self.escaped: set[str] = set()
        self.events: list[MemoryEvent] = []
        self._counter = 0

    @property
    def lattice(self) -> Lattice[dict]:
        return self._lattice

    # -- helpers ------------------------------------------------------------

    def key(self, operand: I.Operand | None) -> str | None:
        if isinstance(operand, I.Name):
            return operand.base if operand.base in self.memory else str(operand)
        return None

    def alloc_of(self, operand: I.Operand | None) -> str | None:
        key = self.key(operand)
        return self.alias.get(key) if key is not None else None

    def _new_alloc(self, loc: Location) -> str:
        self._counter += 1
        alloc = f"alloc#{self._counter}@{loc.line}"
        self.sites[alloc] = loc
        return alloc

    def _emit(self, cwe: str, alloc: str, loc: Location, detail: str) -> None:
        self.events.append(
            MemoryEvent(
                cwe=cwe,
                key=alloc,
                location=loc,
                allocation=self.sites.get(alloc, loc),
                detail=detail,
            )
        )

    # -- transfer functions -------------------------------------------------

    def transfer(self, instr: I.Instr, state: dict, block_label: str) -> dict:
        handler = getattr(self, f"_t_{type(instr).__name__}", None)
        return handler(instr, state) if handler is not None else state

    def transfer_phi(self, phi: I.Phi, state: dict, block_label: str) -> dict:
        dst = self.key(phi.dst)
        if dst is None:
            return state
        for operand, _ in phi.incoming:
            alloc = self.alloc_of(operand)
            if alloc is not None:
                self.alias[dst] = alloc
                break
        return state

    def _t_Assign(self, instr: I.Assign, state: dict) -> dict:
        alloc = self.alloc_of(instr.src)
        dst = self.key(instr.dst)
        if alloc is not None and dst is not None:
            self.alias[dst] = alloc  # a copy is an alias, not a new allocation
        return state

    def _t_BinOp(self, instr: I.BinOp, state: dict) -> dict:
        """A comparison against NULL marks the allocation as checked."""
        if instr.op not in ("==", "!="):
            return state
        for a, b in ((instr.lhs, instr.rhs), (instr.rhs, instr.lhs)):
            alloc = self.alloc_of(a)
            if alloc is not None and isinstance(b, I.Const) and b.value == 0:
                if state.get(alloc) == ALLOCATED:
                    out = dict(state)
                    out[alloc] = CHECKED
                    return out
        return state

    def _t_CBranch(self, instr: I.CBranch, state: dict) -> dict:
        """``if (p)`` is a NULL check even without an explicit comparison."""
        alloc = self.alloc_of(instr.cond)
        if alloc is not None and state.get(alloc) == ALLOCATED:
            out = dict(state)
            out[alloc] = CHECKED
            return out
        return state

    def _t_Call(self, instr: I.Call, state: dict) -> dict:
        out = dict(state)
        if instr.func in ALLOCATORS and instr.dst is not None:
            dst = self.key(instr.dst)
            if dst is not None:
                alloc = self.alias.get(dst) or self._new_alloc(instr.loc)
                self.alias[dst] = alloc
                out[alloc] = ALLOCATED
            return out

        if instr.func in DEALLOCATORS and instr.args:
            alloc = self.alloc_of(instr.args[0])
            if alloc is not None:
                if state.get(alloc) == FREED:
                    self._emit("CWE-415", alloc, instr.loc, "pointer freed a second time")
                    out[alloc] = ERROR
                else:
                    out[alloc] = FREED
            return out

        for arg in instr.args:
            alloc = self.alloc_of(arg)
            if alloc is None:
                continue
            if state.get(alloc) == FREED:
                self._emit("CWE-416", alloc, instr.loc, f"passed to {instr.func}() after free")
            else:
                # Ownership may cross the call boundary; do not report a leak.
                self.escaped.add(alloc)
        return out

    def _t_Load(self, instr: I.Load, state: dict) -> dict:
        self._check_dereference(instr.ptr, instr.loc, state)
        return state

    def _t_Store(self, instr: I.Store, state: dict) -> dict:
        self._check_dereference(instr.ptr, instr.loc, state)
        alloc = self.alloc_of(instr.src)
        if alloc is not None:
            self.escaped.add(alloc)  # stored into memory the caller may reach
        return state

    def _t_Ret(self, instr: I.Ret, state: dict) -> dict:
        alloc = self.alloc_of(instr.src)
        if alloc is not None:
            self.escaped.add(alloc)  # ownership transferred to the caller
        return state

    def _check_dereference(self, operand: I.Operand | None, loc: Location, state: dict) -> None:
        alloc = self.alloc_of(operand)
        if alloc is None:
            return
        status = state.get(alloc)
        if status == FREED:
            self._emit("CWE-416", alloc, loc, "dereferenced after free")
        elif status == ALLOCATED:
            self._emit(
                "CWE-476",
                alloc,
                loc,
                "allocation result dereferenced without checking it against NULL",
            )


@dataclass
class MemoryResult:
    function: str
    analysis: HeapStateAnalysis
    result: DataflowResult
    events: list[MemoryEvent] = field(default_factory=list)


def analyse(cfg: CFG) -> MemoryResult:
    """Run the heap state machine and collect NULL-deref, use-after-free and leaks."""
    analysis = HeapStateAnalysis(cfg)
    result = solve(cfg, analysis)

    # Replay once over the converged states so each event is recorded exactly
    # once, against the fixpoint rather than an intermediate iteration.
    analysis.events.clear()
    for block in cfg:
        state = result.at_block_entry(block.label)
        for instr in block.all_instrs:
            state = (
                analysis.transfer_phi(instr, state, block.label)
                if isinstance(instr, I.Phi)
                else analysis.transfer(instr, state, block.label)
            )

    events = _dedupe(analysis.events)
    events.extend(_leaks(cfg, analysis, result))
    return MemoryResult(function=cfg.name, analysis=analysis, result=result, events=events)


def _dedupe(events: list[MemoryEvent]) -> list[MemoryEvent]:
    seen: set[tuple] = set()
    out: list[MemoryEvent] = []
    for e in events:
        signature = (e.cwe, e.key, e.location.line, e.location.column)
        if signature not in seen:
            seen.add(signature)
            out.append(e)
    return out


def _leaks(cfg: CFG, analysis: HeapStateAnalysis, result: DataflowResult) -> list[MemoryEvent]:
    """Allocations still live at function exit whose ownership never escaped.

    Returning a pointer, storing it into memory, or passing it to another
    function all transfer ownership; reporting those is the classic
    false-positive source in naive leak checkers, so they are excluded.
    """
    exit_state = result.at_block_entry(cfg.exit) or {}
    return [
        MemoryEvent(
            cwe="CWE-401",
            key=alloc,
            location=analysis.sites.get(alloc, cfg.function.loc),
            allocation=analysis.sites.get(alloc, cfg.function.loc),
            detail="allocation reaches function exit with no free on any path",
        )
        for alloc, status in sorted(exit_state.items())
        if status in LIVE_STATES and alloc not in analysis.escaped
    ]


def analyse_program(cfgs: dict[str, CFG]) -> dict[str, MemoryResult]:
    return {name: analyse(cfg) for name, cfg in cfgs.items()}
