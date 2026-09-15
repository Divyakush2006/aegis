"""The dataflow framework and its four instantiations."""
from __future__ import annotations

import pytest

from aegis.analysis import live_vars, memory, reaching_defs
from aegis.analysis.framework import Direction
from aegis.analysis.lattice import FlatLattice, MapLattice, SetLattice
from aegis.analysis.specs import RETURN, SpecTable


class TestLattices:
    def test_set_lattice_is_a_join_semilattice(self):
        lattice = SetLattice()
        a, b = frozenset("ab"), frozenset("bc")
        assert lattice.join(a, b) == frozenset("abc")
        assert lattice.join(a, lattice.bottom()) == a
        assert lattice.leq(lattice.bottom(), a)
        assert lattice.join(a, b) == lattice.join(b, a)  # commutative

    def test_flat_lattice_escalates_monotonically(self):
        lattice = FlatLattice(["NEW", "OPEN", "CLOSED"], error_state="ERR")
        assert lattice.join("NEW", "OPEN") == "OPEN"
        assert lattice.join("OPEN", "CLOSED") == "CLOSED"
        assert lattice.join("OPEN", "ERR") == "ERR"

    def test_map_lattice_joins_pointwise(self):
        lattice = MapLattice(FlatLattice(["A", "B"]))
        assert lattice.join({"x": "A"}, {"x": "B", "y": "A"}) == {"x": "B", "y": "A"}


class TestReachingDefinitions:
    def test_direction_and_convergence(self, compile_source):
        _module, cfgs, _ = compile_source("int f(int n) { n = 1; n = 2; return n; }")
        result = reaching_defs.run(cfgs["f"])
        assert result.analysis.direction is Direction.FORWARD
        assert result.iterations > 0 and not result.widened

    def test_later_definition_kills_earlier(self, compile_source):
        _module, cfgs, _ = compile_source("int f(void) { int x; x = 1; x = 2; return x; }")
        cfg = cfgs["f"]
        result = reaching_defs.run(cfg)
        reaching = result.at_block_entry(cfg.exit)
        for_x = [d for d in reaching if d.variable == "x"]
        assert len(for_x) == 1, "a reassignment must kill the earlier definition"

    def test_both_branches_reach_the_join(self, compile_source):
        """At the merge point, both assignments are still reaching.

        Measured at the join block, not at function exit: the phi inserted at
        the join is itself a definition of ``x`` and kills both, so by the exit
        exactly one definition reaches -- which is the correct answer, not a
        weaker one.
        """
        _module, cfgs, _ = compile_source(
            "int f(int n) { int x; if (n) { x = 1; } else { x = 2; } return x; }"
        )
        cfg = cfgs["f"]
        result = reaching_defs.run(cfg)
        join = next(b.label for b in cfg if any(p.dst.base == "x" for p in b.phis))
        reaching = result.at_block_entry(join)
        assert len([d for d in reaching if d.variable == "x"]) == 2
        assert len([d for d in result.at_block_entry(cfg.exit) if d.variable == "x"]) == 1


class TestLiveVariables:
    def test_is_backward(self, compile_source):
        _module, cfgs, _ = compile_source("int f(int n) { return n; }")
        assert live_vars.run(cfgs["f"]).analysis.direction is Direction.BACKWARD

    def test_value_used_later_is_live(self, compile_source):
        _module, cfgs, _ = compile_source(
            "int f(int n) { int t; t = n + 1; return t; }"
        )
        cfg = cfgs["f"]
        result = live_vars.run(cfg)
        assert any("n" in name for name in result.at_block_entry(cfg.entry))

    def test_initialiser_feeding_a_phi_stays_live(self, compile_source):
        """A phi operand must be live on the edge it arrives from.

        Only the ``then`` branch reassigns ``t``, so ``t = 0`` reaches the join
        through the fall-through edge and is genuinely live. Reporting it dead
        is what happens when phi operands are not handled on their own edges --
        the case the framework's edge transfer function exists for.
        """
        _module, cfgs, _ = compile_source(
            "int f(int n) { int t; t = 0; if (n) { t = 1; } return t; }"
        )
        assert live_vars.dead_stores(cfgs["f"]) == []

    def test_store_overwritten_on_every_path_is_dead(self, compile_source):
        """The converse: when both branches reassign, the initialiser is dead."""
        _module, cfgs, _ = compile_source(
            "int f(int n) { int t; t = 0; if (n) { t = 1; } else { t = 2; } return t; }"
        )
        dead = live_vars.dead_stores(cfgs["f"])
        assert any(str(instr).endswith("= 0") for instr in dead)

    def test_genuinely_dead_store_is_reported(self, compile_source):
        _module, cfgs, _ = compile_source("int f(int n) { int x; x = 99; return n; }")
        dead = live_vars.dead_stores(cfgs["f"])
        assert any("99" in str(instr) for instr in dead)


class TestTaint:
    def test_direct_source_to_sink(self, analyse):
        _cfgs, result = analyse(
            "int main(void) { char b[64]; fgets(b, 64, stdin); system(b); return 0; }"
        )
        hits = [h for _f, _r, h in result.all_sink_hits()]
        assert any(h.cwe == "CWE-78" for h in hits)

    def test_constant_into_sink_is_not_reported(self, analyse):
        _cfgs, result = analyse('int main(void) { system("ls -l"); return 0; }')
        assert list(result.all_sink_hits()) == []

    def test_sanitizer_breaks_the_path(self, analyse):
        _cfgs, result = analyse(
            "char *escape_shell(char *s);\n"
            "int main(void) { char b[64]; char *c; fgets(b, 64, stdin);"
            " c = escape_shell(b); system(c); return 0; }"
        )
        assert list(result.all_sink_hits()) == []

    def test_format_string_position_is_per_function(self, analyse):
        source = (
            "int main(void) { char b[64]; fgets(b, 64, stdin);"
            ' printf(b); printf("%s", b); return 0; }'
        )
        _cfgs, result = analyse(source)
        format_hits = [h for _f, _r, h in result.all_sink_hits() if h.cwe == "CWE-134"]
        assert len(format_hits) == 1, "only the bare printf(b) is a format-string sink"

    def test_path_is_reconstructed_with_every_hop(self, analyse):
        _cfgs, result = analyse(
            "int main(void) { char b[64]; char c[128]; fgets(b, 64, stdin);"
            ' sprintf(c, "echo %s", b); system(c); return 0; }'
        )
        for _fn, taint_result, hit in result.all_sink_hits():
            if hit.cwe != "CWE-78":
                continue
            path = taint_result.path_to(hit)
            assert len(path) >= 2
            assert path[0][1] is not None, "the source step must name an instruction"
            return
        pytest.fail("expected a CWE-78 finding")


class TestInterprocedural:
    SOURCE = (
        "void wrap(char *in, char *out) { strcpy(out, in); }\n"
        "int main(int argc, char **argv) {\n"
        "    char cmd[128];\n"
        "    wrap(argv[1], cmd);\n"
        "    system(cmd);\n"
        "    return 0;\n"
        "}\n"
    )

    def test_summary_records_parameter_flow(self, analyse):
        _cfgs, result = analyse(self.SOURCE)
        summary = result.summaries["wrap"]
        assert 1 in summary.param_flows[0], "param0 must be seen flowing to param1"

    def test_cross_function_taint_reaches_the_sink(self, analyse):
        _cfgs, result = analyse(self.SOURCE)
        assert any(h.cwe == "CWE-78" for _f, _r, h in result.all_sink_hits())

    def test_callgraph_records_external_calls(self, analyse):
        _cfgs, result = analyse(self.SOURCE)
        assert "system" in result.callgraph.externals()

    def test_summaries_computed_callee_before_caller(self, analyse):
        _cfgs, result = analyse(self.SOURCE)
        order = [name for group in result.callgraph.reverse_topological() for name in group]
        assert order.index("wrap") < order.index("main")

    def test_recursion_terminates(self, analyse):
        source = (
            "int fact(int n) { if (n <= 1) { return 1; } return n * fact(n - 1); }\n"
            "int main(void) { return fact(5); }\n"
        )
        _cfgs, result = analyse(source)
        assert "fact" in result.summaries  # reached fixpoint without hanging

    def test_sanitizing_wrapper_is_summarised_as_safe(self, analyse):
        source = (
            "char *escape_shell(char *s);\n"
            "char *clean(char *in) { return escape_shell(in); }\n"
            "int main(int argc, char **argv) { system(clean(argv[1])); return 0; }\n"
        )
        _cfgs, result = analyse(source)
        assert list(result.all_sink_hits()) == []


class TestHeapStateMachine:
    def _events(self, compile_source, source):
        _module, cfgs, _ = compile_source(source)
        out = []
        for cfg in cfgs.values():
            out.extend(memory.analyse(cfg).events)
        return out

    def test_leak_detected(self, compile_source):
        events = self._events(
            compile_source, "int f(void) { char *p; p = malloc(8); return 0; }"
        )
        assert any(e.cwe == "CWE-401" for e in events)

    def test_returned_allocation_is_not_a_leak(self, compile_source):
        events = self._events(
            compile_source, "char *f(void) { char *p; p = malloc(8); return p; }"
        )
        assert not any(e.cwe == "CWE-401" for e in events)

    def test_freed_allocation_is_not_a_leak(self, compile_source):
        events = self._events(
            compile_source, "int f(void) { char *p; p = malloc(8); free(p); return 0; }"
        )
        assert not any(e.cwe == "CWE-401" for e in events)

    def test_use_after_free(self, compile_source):
        events = self._events(
            compile_source,
            "int f(void) { char *p; p = malloc(8); free(p); p[0] = 1; return 0; }",
        )
        assert any(e.cwe == "CWE-416" for e in events)

    def test_double_free(self, compile_source):
        events = self._events(
            compile_source, "int f(void) { char *p; p = malloc(8); free(p); free(p); return 0; }"
        )
        assert any(e.cwe == "CWE-415" for e in events)

    def test_unchecked_allocation_dereference(self, compile_source):
        events = self._events(
            compile_source, "int f(void) { char *p; p = malloc(8); p[0] = 1; free(p); return 0; }"
        )
        assert any(e.cwe == "CWE-476" for e in events)

    def test_null_check_suppresses_the_report(self, compile_source):
        events = self._events(
            compile_source,
            "int f(void) { char *p; p = malloc(8); if (p == 0) { return 1; }"
            " p[0] = 1; free(p); return 0; }",
        )
        assert not any(e.cwe == "CWE-476" for e in events)

    def test_alias_is_not_counted_as_a_second_allocation(self, compile_source):
        events = self._events(
            compile_source,
            "int f(void) { char *p; char *q; p = malloc(8); q = p; free(q); return 0; }",
        )
        assert events == []


class TestSpecTable:
    def test_merging_preserves_both_roles(self):
        table = SpecTable()
        strcpy = table.get("strcpy")
        assert strcpy.propagates and strcpy.sinks  # propagator and CWE-120 sink

    def test_return_position_resolves(self):
        assert RETURN in SpecTable().get("getenv").taints

    def test_serialisable_for_the_cache(self):
        entries = SpecTable().as_dicts()
        assert all({"name", "role", "origin"} <= set(e) for e in entries)
