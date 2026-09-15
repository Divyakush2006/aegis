"""IR lowering, CFG construction, dominance and SSA.

The dominance frontier test is the important one: phi placement is a stated
deliverable, and the implementation is cross-checked against networkx's
independent implementation on every program in the suite.
"""
from __future__ import annotations

import networkx as nx
import pytest

from prahari.ir import instructions as I
from prahari.ir.ssa import verify_ssa


class TestLowering:
    def test_control_flow_becomes_explicit(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { if (n > 0) { return 1; } else { return 2; } }"
        )
        cfg = cfgs["f"]
        terminators = [b.terminator for b in cfg if b.terminator]
        assert any(isinstance(t, I.CBranch) for t in terminators)

    def test_short_circuit_creates_real_branches(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int a, int b) { if (a > 0 && b > 0) { return 1; } return 0; }"
        )
        cfg = cfgs["f"]
        branches = [b for b in cfg if isinstance(b.terminator, I.CBranch)]
        # One branch for the && itself, one for the enclosing if.
        assert len(branches) >= 2

    def test_shadowed_declarations_get_distinct_names(self, compile_source):
        module, _cfgs, _ = compile_source(
            "int f(void) { int x; x = 1; { int x; x = 2; } return 0; }"
        )
        names = set(module.functions["f"].locals)
        assert "x" in names and "x$1" in names

    def test_every_instruction_carries_a_location(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { int i; for (i = 0; i < n; i++) { n = n - 1; } return n; }"
        )
        for cfg in cfgs.values():
            for block in cfg:
                for instr in block.instrs:
                    assert instr.loc.line > 0, f"{instr} has no source line"

    def test_arrays_are_memory_not_ssa_values(self, compile_source):
        module, _cfgs, _ = compile_source("int f(void) { char b[8]; b[0] = 1; return 0; }")
        assert "b" in module.functions["f"].memory_vars


class TestCFG:
    def test_entry_and_exit_exist(self, compile_source):
        _module, cfgs, _ = compile_source("int f(void) { return 0; }")
        cfg = cfgs["f"]
        assert cfg.entry in cfg.blocks and cfg.exit in cfg.blocks

    def test_loop_produces_a_back_edge(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { while (n > 0) { n = n - 1; } return n; }"
        )
        cfg = cfgs["f"]
        assert not nx.is_directed_acyclic_graph(cfg.graph)

    def test_unreachable_blocks_are_pruned(self, compile_source):
        _module, cfgs, _ = compile_source("int f(void) { return 1; return 2; }")
        cfg = cfgs["f"]
        for label in cfg.blocks:
            assert label == cfg.entry or nx.has_path(cfg.graph, cfg.entry, label)

    def test_dominance_is_transitive_to_entry(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { if (n) { n = 1; } else { n = 2; } return n; }"
        )
        cfg = cfgs["f"]
        for label in cfg.blocks:
            assert cfg.dominates(cfg.entry, label)


class TestDominanceFrontiers:
    """Our Cooper-Harvey-Kennedy implementation must match networkx exactly."""

    SOURCES = [
        "int f(void) { return 0; }",
        "int f(int n) { if (n) { n = 1; } return n; }",
        "int f(int n) { if (n) { n = 1; } else { n = 2; } return n; }",
        "int f(int n) { while (n > 0) { n = n - 1; } return n; }",
        "int f(int n) { int i; for (i = 0; i < n; i++) { n = n + i; } return n; }",
        "int f(int n) { int i; for (i = 0; i < n; i++) { if (i) { n++; } else { n--; } } return n; }",
        "int f(int n) { while (n) { if (n > 5) { break; } n++; } return n; }",
        "int f(int n) { do { n--; } while (n > 0); return n; }",
        "int f(int n) { switch (n) { case 1: n = 10; break; default: n = 0; } return n; }",
    ]

    @pytest.mark.parametrize("source", SOURCES)
    def test_matches_networkx(self, compile_source, source):
        _module, cfgs, _ = compile_source(source)
        cfg = cfgs["f"]
        ours = {k: v for k, v in cfg.dominance_frontiers.items() if v}
        theirs = {
            k: set(v) for k, v in nx.dominance_frontiers(cfg.graph, cfg.entry).items() if v
        }
        assert ours == theirs

    @pytest.mark.parametrize("source", SOURCES)
    def test_immediate_dominators_match(self, compile_source, source):
        _module, cfgs, _ = compile_source(source)
        cfg = cfgs["f"]
        assert cfg.idom == nx.immediate_dominators(cfg.graph, cfg.entry)


class TestSSA:
    @pytest.mark.parametrize("source", TestDominanceFrontiers.SOURCES)
    def test_single_assignment_invariant_holds(self, compile_source, source):
        _module, cfgs, _ = compile_source(source)
        for cfg in cfgs.values():
            assert verify_ssa(cfg) == []

    def test_examples_are_well_formed(self, example_files, audit):
        from prahari.index import build_index

        index = build_index(example_files)
        violations = []
        for cfg in index.cfgs.values():
            violations.extend(verify_ssa(cfg))
        assert violations == []

    def test_phi_placed_at_loop_header(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { int t; t = 0; while (n > 0) { t = t + n; n = n - 1; } return t; }"
        )
        cfg = cfgs["f"]
        phi_targets = {
            phi.dst.base for block in cfg for phi in block.phis
        }
        assert {"t", "n"} <= phi_targets

    def test_dead_phis_are_pruned(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { int i; for (i = 0; i < n; i++) { n = n + i * 2; } return n; }"
        )
        cfg = cfgs["f"]
        used = {str(u) for block in cfg for ins in block.all_instrs for u in ins.uses}
        for block in cfg:
            for phi in block.phis:
                assert str(phi.dst) in used, f"{phi} is dead and should have been pruned"

    def test_phi_operand_count_matches_predecessors(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { int t; t = 0; if (n) { t = 1; } else { t = 2; } return t; }"
        )
        cfg = cfgs["f"]
        for block in cfg:
            for phi in block.phis:
                assert {p for _, p in phi.incoming} == set(cfg.preds(block.label))
