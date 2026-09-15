"""SSA construction: phi placement over dominance frontiers, then renaming.

This is the classical Cytron et al. algorithm. Two deliberate restrictions:

* Only *renameable* variables are versioned -- scalars that are neither arrays,
  structs, nor address-taken. Everything else stays in ``memory_vars`` and is
  modelled by its base name. The analysed subset has no pointer arithmetic, so
  a base-name memory model is sound for it; that is the scope boundary the
  project documents state, made concrete.
* Phi nodes live in ``BasicBlock.phis`` rather than the instruction list, so
  the dataflow framework can treat them as block-entry operations.

Why SSA matters for this project specifically: taint becomes a property of a
*definition* rather than of a variable, so no kill sets are needed and a
tainted value stays distinguishable from a later safe value of the same name.
"""
from __future__ import annotations

from collections import defaultdict

from . import instructions as I
from .cfg import CFG


class SSABuilder:
    """Converts one function's CFG into SSA form in place."""

    def __init__(self, cfg: CFG) -> None:
        self.cfg = cfg
        self.function = cfg.function
        self.memory = set(self.function.memory_vars)
        self.counter: dict[str, int] = defaultdict(int)
        self.stacks: dict[str, list[int]] = defaultdict(list)
        self.renameable: set[str] = set()

    # -- public API ---------------------------------------------------------

    def run(self) -> CFG:
        self.renameable = self._collect_renameable()
        self._insert_phis()
        self._rename(self.cfg.entry)
        return self.cfg

    # -- step 1: which names can be versioned -------------------------------

    def _collect_renameable(self) -> set[str]:
        names: set[str] = set()
        for block in self.cfg:
            for instr in block.instrs:
                for d in instr.defs:
                    if d.name not in self.memory:
                        names.add(d.name)
        for p in self.function.params:
            if p.name not in self.memory:
                names.add(p.name)
        return names

    # -- step 2: phi placement ----------------------------------------------

    def _defsites(self) -> dict[str, set[str]]:
        sites: dict[str, set[str]] = defaultdict(set)
        for block in self.cfg:
            for instr in block.instrs:
                for d in instr.defs:
                    if d.name in self.renameable:
                        sites[d.name].add(block.label)
        for p in self.function.params:
            if p.name in self.renameable:
                sites[p.name].add(self.cfg.entry)
        return sites

    def _insert_phis(self) -> None:
        frontiers = self.cfg.dominance_frontiers
        defsites = self._defsites()

        for var, sites in defsites.items():
            placed: set[str] = set()
            worklist = list(sites)
            while worklist:
                block_label = worklist.pop()
                for frontier in frontiers.get(block_label, ()):  # iterated DF
                    if frontier in placed:
                        continue
                    target = self.cfg.blocks.get(frontier)
                    if target is None:
                        continue
                    preds = self.cfg.preds(frontier)
                    phi = I.Phi(
                        dst=I.Name(var),
                        incoming=[(I.Name(var), p) for p in preds],
                        loc=target.loc,
                    )
                    target.phis.append(phi)
                    placed.add(frontier)
                    if frontier not in sites:
                        worklist.append(frontier)

    # -- step 3: renaming ---------------------------------------------------

    def _new_version(self, var: str) -> int:
        self.counter[var] += 1
        version = self.counter[var]
        self.stacks[var].append(version)
        return version

    def _top(self, var: str) -> int | None:
        stack = self.stacks[var]
        return stack[-1] if stack else None

    def _current(self, var: str) -> I.Name:
        version = self._top(var)
        return I.Name(var, version if version is not None else 0)

    def _rename(self, label: str) -> None:
        block = self.cfg.blocks.get(label)
        if block is None:
            return
        pushed: list[str] = []

        if label == self.cfg.entry:
            for p in self.function.params:
                if p.name in self.renameable:
                    self._new_version(p.name)
                    pushed.append(p.name)

        for phi in block.phis:
            var = phi.dst.name
            phi.replace_def(I.Name(var, self._new_version(var)))
            pushed.append(var)

        for instr in block.instrs:
            if not isinstance(instr, I.Phi):
                mapping = {
                    u.name: self._current(u.name)
                    for u in instr.uses
                    if u.name in self.renameable
                }
                if mapping:
                    instr.replace_uses(mapping)
            for d in instr.defs:
                if d.name in self.renameable:
                    instr.replace_def(I.Name(d.name, self._new_version(d.name)))
                    pushed.append(d.name)

        for succ in self.cfg.succs(label):
            target = self.cfg.blocks.get(succ)
            if target is None:
                continue
            for phi in target.phis:
                var = phi.dst.name
                phi.incoming = [
                    (self._current(var) if pred == label else operand, pred)
                    for operand, pred in phi.incoming
                ]

        for child in self._dom_children(label):
            self._rename(child)

        for var in pushed:
            if self.stacks[var]:
                self.stacks[var].pop()

    def _dom_children(self, label: str) -> list[str]:
        return [n for n, parent in self.cfg.idom.items() if parent == label and n != label]


def prune_dead_phis(cfg: CFG) -> int:
    """Remove phi nodes whose result is never read, to fixpoint.

    Minimal SSA (Cytron) places a phi wherever a definition reaches a join,
    which for short-lived temporaries produces phis that nothing consumes.
    Dropping them yields pruned SSA without needing a liveness pass first, and
    makes the IR dump readable enough to include in the report.
    """
    # Names read by something that is not a phi. A phi justified only by another
    # phi is not justified at all -- loop-carried temporaries form exactly such
    # cycles, and a naive "has any use" test never removes them.
    live: set[str] = set()
    for block in cfg:
        for instr in block.instrs:
            for u in instr.uses:
                live.add(str(u))

    all_phis = [p for block in cfg for p in block.phis]
    changed = True
    while changed:
        changed = False
        for phi in all_phis:
            if str(phi.dst) in live:
                for operand, _ in phi.incoming:
                    if str(operand) not in live:
                        live.add(str(operand))
                        changed = True

    removed = 0
    for block in cfg:
        keep = [p for p in block.phis if str(p.dst) in live]
        removed += len(block.phis) - len(keep)
        block.phis = keep
    return removed


def to_ssa(cfg: CFG, prune: bool = True) -> CFG:
    """Convert a CFG to SSA form in place and return it."""
    SSABuilder(cfg).run()
    if prune:
        prune_dead_phis(cfg)
    return cfg


def build_ssa(cfgs: dict[str, CFG]) -> dict[str, CFG]:
    for cfg in cfgs.values():
        to_ssa(cfg)
    return cfgs


def verify_ssa(cfg: CFG) -> list[str]:
    """Return a list of SSA invariant violations (empty when well-formed).

    Checks the single-assignment property for every versioned name. Used by the
    test suite as the acceptance criterion for phi placement.
    """
    seen: dict[str, str] = {}
    errors: list[str] = []
    for block in cfg:
        for instr in block.all_instrs:
            for d in instr.defs:
                if d.version is None:
                    continue
                key = str(d)
                if key in seen:
                    errors.append(
                        f"{cfg.name}: {key} defined twice (blocks {seen[key]} and {block.label})"
                    )
                else:
                    seen[key] = block.label
    for block in cfg:
        for phi in block.phis:
            preds = set(cfg.preds(block.label))
            got = {p for _, p in phi.incoming}
            if got != preds:
                errors.append(
                    f"{cfg.name}: phi {phi.dst} in {block.label} has operands for {sorted(got)}, "
                    f"predecessors are {sorted(preds)}"
                )
    return errors
