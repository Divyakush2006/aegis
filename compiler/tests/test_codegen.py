"""LLVM code generation.

These tests JIT-compile and *execute* the generated code and check the answer.
Verifying that IR merely parses proves nothing about whether the compiler is
correct; running it does. This is also what makes the project's central claim
literally true -- remove every analysis and a working compiler remains.
"""
from __future__ import annotations

import pytest

from prahari.codegen import llvm_emitter
from prahari.frontend.adapter import parse_source
from prahari.ir.lowering import lower_program

pytestmark = pytest.mark.skipif(
    not llvm_emitter.LLVM_AVAILABLE, reason="llvmlite is not installed"
)


def build(source: str):
    program, _pre, exclusions = parse_source(source, "<codegen>")
    return lower_program(program, exclusions)


def run(source: str, function: str = "main", *args: int) -> int:
    return llvm_emitter.jit_call(build(source), function, *args)


class TestEmission:
    def test_module_verifies(self):
        module = build("int f(int n) { return n + 1; }")
        llvm_emitter.verify(module)  # raises if malformed

    def test_ir_declares_the_function(self):
        text = llvm_emitter.emit_ir(build("int square(int n) { return n * n; }"))
        assert "define i32 @" in text and "square" in text

    def test_native_assembly_is_produced(self):
        asm = llvm_emitter.emit_assembly(build("int f(int n) { return n * n; }"))
        assert len(asm.splitlines()) > 5

    def test_object_file_is_produced(self):
        data = llvm_emitter.emit_object(build("int f(int n) { return n; }"))
        assert isinstance(data, bytes) and len(data) > 100

    def test_optimisation_levels_all_work(self):
        module = build("int f(int n) { int t; t = n + 0; return t * 1; }")
        for level in (0, 1, 2, 3):
            assert llvm_emitter.emit_object(module, optimise=level)


class TestExecution:
    """Compile and run: the answer has to be right, not just well-formed."""

    @pytest.mark.parametrize(
        "source, function, args, expected",
        [
            ("int f(int n) { return n * n; }", "f", (7,), 49),
            ("int f(int n) { return n + 1; }", "f", (41,), 42),
            ("int f(int a) { return -a; }", "f", (5,), -5),
            ("int f(int n) { return n % 7; }", "f", (23,), 2),
            ("int f(int n) { return n / 3; }", "f", (22,), 7),
            ("int f(int n) { return !n; }", "f", (0,), 1),
            ("int f(int a) { return a > 3; }", "f", (10,), 1),
            ("int f(int a) { return a > 3; }", "f", (1,), 0),
        ],
    )
    def test_expressions(self, source, function, args, expected):
        assert run(source, function, *args) == expected

    def test_if_else(self):
        source = "int f(int n) { if (n > 10) { return 1; } else { return 2; } }"
        assert run(source, "f", 20) == 1
        assert run(source, "f", 5) == 2

    def test_while_loop(self):
        source = "int f(int n) { int t; t = 0; while (n > 0) { t = t + n; n = n - 1; } return t; }"
        assert run(source, "f", 10) == 55

    def test_for_loop(self):
        source = "int f(int n) { int i; int t; t = 0; for (i = 1; i <= n; i++) { t = t + i; } return t; }"
        assert run(source, "f", 100) == 5050

    def test_do_while(self):
        source = "int f(int n) { int t; t = 0; do { t = t + 1; n = n - 1; } while (n > 0); return t; }"
        assert run(source, "f", 4) == 4

    def test_nested_loop_with_break(self):
        source = (
            "int f(int n) { int i; int t; t = 0;"
            " for (i = 0; i < n; i++) { if (i > 4) { break; } t = t + i; } return t; }"
        )
        assert run(source, "f", 100) == 10  # 0+1+2+3+4

    def test_continue(self):
        source = (
            "int f(int n) { int i; int t; t = 0;"
            " for (i = 0; i < n; i++) { if (i % 2 == 0) { continue; } t = t + i; } return t; }"
        )
        assert run(source, "f", 10) == 25  # 1+3+5+7+9

    def test_recursion(self):
        source = "int fact(int n) { if (n <= 1) { return 1; } return n * fact(n - 1); }"
        assert run(source, "fact", 6) == 720

    def test_mutual_recursion(self):
        source = (
            "int odd(int n);\n"
            "int even(int n) { if (n == 0) { return 1; } return odd(n - 1); }\n"
            "int odd(int n) { if (n == 0) { return 0; } return even(n - 1); }\n"
        )
        assert run(source, "even", 10) == 1
        assert run(source, "even", 7) == 0

    def test_short_circuit_and(self):
        source = "int f(int a, int b) { if (a > 0 && b > 0) { return 1; } return 0; }"
        module = build(source)
        assert llvm_emitter.jit_call(module, "f", 1, 1) == 1
        assert llvm_emitter.jit_call(module, "f", 1, 0) == 0
        assert llvm_emitter.jit_call(module, "f", 0, 1) == 0

    def test_short_circuit_or(self):
        source = "int f(int a, int b) { if (a > 0 || b > 0) { return 1; } return 0; }"
        module = build(source)
        assert llvm_emitter.jit_call(module, "f", 0, 1) == 1
        assert llvm_emitter.jit_call(module, "f", 0, 0) == 0

    def test_ternary(self):
        source = "int f(int n) { return n > 0 ? n : 0 - n; }"
        module = build(source)
        assert llvm_emitter.jit_call(module, "f", -9) == 9
        assert llvm_emitter.jit_call(module, "f", 9) == 9

    def test_switch(self):
        source = (
            "int f(int n) { int r; r = 0;"
            " switch (n) { case 1: r = 10; break; case 2: r = 20; break; default: r = 99; }"
            " return r; }"
        )
        module = build(source)
        assert llvm_emitter.jit_call(module, "f", 1) == 10
        assert llvm_emitter.jit_call(module, "f", 2) == 20
        assert llvm_emitter.jit_call(module, "f", 7) == 99

    def test_array_indexing(self):
        source = (
            "int f(void) { int a[4]; a[0] = 10; a[1] = 20; a[2] = 30; "
            "return a[0] + a[1] + a[2]; }"
        )
        assert run(source, "f") == 60

    def test_array_in_a_loop(self):
        source = (
            "int f(int n) { int a[8]; int i; int t;"
            " for (i = 0; i < 8; i++) { a[i] = i * 2; }"
            " t = 0; for (i = 0; i < 8; i++) { t = t + a[i]; } return t; }"
        )
        assert run(source, "f", 0) == 56  # 2*(0+1+..+7)

    def test_compound_assignment(self):
        source = "int f(int n) { n += 10; n *= 2; n -= 4; return n; }"
        assert run(source, "f", 1) == 18

    def test_global_variable(self):
        source = "int counter; int f(int n) { counter = n; counter = counter + 1; return counter; }"
        assert run(source, "f", 41) == 42

    def test_variable_shadowing_is_preserved(self):
        source = "int f(void) { int x; x = 1; { int x; x = 99; } return x; }"
        assert run(source, "f") == 1


class TestEscapeDecoding:
    """String escapes must be decoded in the front end, not left to the backend."""

    @staticmethod
    def _global(program, name):
        # The libc prelude declares stdin/stdout/stderr, so look up by name
        # rather than by position.
        return next(g for g in program.globals if g.name == name)

    def test_newline_is_a_real_byte(self):
        program, _pre, _ = parse_source(r'char *s = "a\nb";', "t.c")
        assert self._global(program, "s").init.value == "a\nb"

    def test_hex_and_octal(self):
        program, _pre, _ = parse_source(r'char *s = "\x41\101";', "t.c")
        assert self._global(program, "s").init.value == "AA"

    def test_emitted_ir_contains_the_decoded_bytes(self):
        text = llvm_emitter.emit_ir(build('int puts(const char *s); int f(void) { return puts("hi\\n"); }'))
        assert "\\0A" in text or "\\0a" in text  # the newline byte, not a literal backslash


class TestErrors:
    def test_ssa_form_is_rejected_with_a_clear_message(self):
        """Codegen consumes the pre-SSA list; phis are LLVM's job."""
        from prahari.ir.cfg import build_cfgs
        from prahari.ir.ssa import build_ssa

        module = build("int f(int n) { int t; t = 0; if (n) { t = 1; } return t; }")
        cfgs = build_cfgs(module)
        build_ssa(cfgs)
        phis = [p for cfg in cfgs.values() for b in cfg for p in b.phis]
        assert phis, "expected the SSA form to contain phi nodes"
        emitter = llvm_emitter.FunctionEmitter(
            module=llvm_emitter.LLVMEmitter(module).module,
            function=module.functions["f"],
            externals={},
            globals_={},
        )
        with pytest.raises(llvm_emitter.CodegenError, match="phi"):
            emitter._e_Phi(phis[0])
