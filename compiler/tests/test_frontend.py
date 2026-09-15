"""Front end: preprocessing, parsing, and the AegisAST boundary."""
from __future__ import annotations

import pytest

from aegis.frontend.adapter import parse_source
from aegis.frontend.preprocess import preprocess, strip_comments


class TestPreprocessor:
    def test_line_numbers_survive_include_elision(self):
        source = "#include <stdio.h>\n#include <string.h>\nint main(void) { return 0; }\n"
        program, pre, _ = parse_source(source, "t.c")
        assert pre.dropped_includes == ["<stdio.h>", "<string.h>"]
        # main is on source line 3 and must still report line 3.
        assert program.function("main").loc.line == 3

    def test_comments_do_not_shift_line_numbers(self):
        source = (
            "/* a\n"
            "   multi-line\n"
            "   comment */\n"
            "int main(void) { return 0; }\n"
        )
        program, _pre, _ = parse_source(source, "t.c")
        assert program.function("main").loc.line == 4

    def test_string_containing_comment_syntax_survives(self):
        stripped = strip_comments('char *s = "/* keep */"; // drop\n')
        assert "/* keep */" in stripped
        assert "drop" not in stripped

    def test_conditional_compilation(self):
        source = (
            "#define ENABLED 1\n"
            "#ifdef ENABLED\n"
            "int chosen(void) { return 1; }\n"
            "#else\n"
            "int rejected(void) { return 0; }\n"
            "#endif\n"
        )
        program, _pre, _ = parse_source(source, "t.c")
        names = {f.name for f in program.definitions}
        assert names == {"chosen"}

    def test_ifndef_branch_is_taken_when_undefined(self):
        source = "#ifndef OMITBAD\nint bad(void) { return 1; }\n#endif\n"
        program, _pre, _ = parse_source(source, "t.c")
        assert program.function("bad") is not None

    def test_prelude_declares_modelled_libc(self):
        result = preprocess("int main(void) { return 0; }", "t.c")
        for name in ("system", "strcpy", "fgets", "malloc", "printf"):
            assert name in result.text


class TestAdapter:
    def test_produces_aegis_ast_not_pycparser_nodes(self):
        program, _pre, _ = parse_source("int f(int a) { return a + 1; }", "t.c")
        func = program.function("f")
        assert type(func).__module__.endswith("ast_nodes")

    def test_signature_and_types(self):
        program, _pre, _ = parse_source("char *g(char *s, int n) { return s; }", "t.c")
        func = program.function("g")
        assert [str(p.type) for p in func.params] == ["char*", "int"]
        assert str(func.return_type) == "char*"

    def test_array_extent_is_recorded(self, ):
        program, _pre, _ = parse_source("int f(void) { char buf[64]; return 0; }", "t.c")
        decl = program.function("f").body.stmts[0]
        assert decl.type.kind == "array" and decl.type.size == 64

    @pytest.mark.parametrize(
        "source, construct",
        [
            ("int f(void) { goto end; end: return 0; }", "goto/label"),
            ("int f(int (*cb)(int)) { return 0; }", "function pointer parameter"),
            ("int f(int n, ...) { return n; }", "variadic user function"),
        ],
    )
    def test_out_of_subset_constructs_are_excluded_not_crashed(self, source, construct):
        program, _pre, exclusions = parse_source(source, "t.c")
        assert any(e.construct == construct for e in exclusions), [
            e.construct for e in exclusions
        ]
        assert program is not None  # the file still parsed

    def test_one_bad_function_does_not_lose_the_others(self):
        source = (
            "int good(void) { return 1; }\n"
            "int bad(void) { goto out; out: return 0; }\n"
            "int alsogood(void) { return 2; }\n"
        )
        program, _pre, exclusions = parse_source(source, "t.c")
        names = {f.name for f in program.definitions}
        assert names == {"good", "alsogood"}
        assert len(exclusions) == 1
