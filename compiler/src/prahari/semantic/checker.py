"""Semantic analysis: scope resolution and type checking.

Produces the diagnostics the editor shows as squiggles, and annotates the AST
with resolved types. Every check here is one a compiler must perform anyway; the
security analysis downstream assumes a well-formed, resolved program.

The checker reports rather than raises, so a file with a type error is still
analysed for vulnerabilities -- which is the behaviour a security tool needs, as
real code under review is often mid-edit.
"""
from __future__ import annotations

from ..diagnostics import Diagnostic, Location, Severity
from ..frontend import ast_nodes as A
from . import types as T
from .symbol_table import Symbol, SymbolTable


class TypeChecker:
    """Resolves identifiers and checks types across a whole program."""

    def __init__(self, program: A.Program) -> None:
        self.program = program
        self.table = SymbolTable()
        self.diagnostics: list[Diagnostic] = []
        self.current_function: A.FuncDecl | None = None

    # -- reporting ----------------------------------------------------------

    def error(self, code: str, message: str, loc: Location) -> None:
        self.diagnostics.append(Diagnostic(Severity.ERROR, code, message, loc))

    def warn(self, code: str, message: str, loc: Location) -> None:
        self.diagnostics.append(Diagnostic(Severity.WARNING, code, message, loc))

    # -- entry point --------------------------------------------------------

    def run(self) -> list[Diagnostic]:
        for g in self.program.globals:
            self.table.declare(
                Symbol(g.name, g.type or A.INT, "global", g.loc)
            )
        for f in self.program.functions:
            symbol = Symbol(
                name=f.name,
                type=f.return_type or A.INT,
                kind="function",
                location=f.loc,
                is_defined=f.is_definition,
                params=[p.type for p in f.params],
                is_variadic=f.is_variadic,
            )
            existing = self.table.global_scope.declare(symbol)
            if existing is not None and existing.is_defined and f.is_definition:
                self.error("E001", f"redefinition of function '{f.name}'", f.loc)
            elif existing is not None and f.is_definition:
                self.table.global_scope.symbols[f.name] = symbol

        for f in self.program.functions:
            if f.is_definition:
                self.check_function(f)
        return self.diagnostics

    def check_function(self, func: A.FuncDecl) -> None:
        self.current_function = func
        scope = self.table.push("function")
        self.table.function_scopes[func.name] = scope
        for p in func.params:
            if self.table.current.declare(Symbol(p.name, p.type, "parameter", p.loc)):
                self.error("E002", f"duplicate parameter '{p.name}'", p.loc)
        self.check_stmt(func.body)
        self.table.pop()
        self.current_function = None

    # -- statements ---------------------------------------------------------

    def check_stmt(self, node) -> None:
        if node is None:
            return
        method = getattr(self, f"_s_{type(node).__name__}", None)
        if method is not None:
            method(node)

    def _s_Block(self, node: A.Block) -> None:
        self.table.push("block")
        for s in node.stmts:
            self.check_stmt(s)
        self.table.pop()

    def _s_VarDecl(self, node: A.VarDecl) -> None:
        if self.table.current.lookup_local(node.name) is not None:
            self.error("E003", f"redeclaration of '{node.name}'", node.loc)
        else:
            self.table.declare(Symbol(node.name, node.type or A.INT, "variable", node.loc))
        if node.init is not None:
            value = self.check_expr(node.init)
            if not T.compatible(node.type, value):
                self.error(
                    "E004",
                    f"cannot initialise '{node.name}' of type {node.type} with {value}",
                    node.loc,
                )

    def _s_ExprStmt(self, node: A.ExprStmt) -> None:
        self.check_expr(node.expr)

    def _s_If(self, node: A.If) -> None:
        self.check_expr(node.cond)
        self.check_stmt(node.then)
        self.check_stmt(node.otherwise)

    def _s_While(self, node: A.While) -> None:
        self.check_expr(node.cond)
        self.check_stmt(node.body)

    def _s_For(self, node: A.For) -> None:
        self.table.push("block")
        self.check_stmt(node.init)
        self.check_expr(node.cond)
        self.check_expr(node.step)
        self.check_stmt(node.body)
        self.table.pop()

    def _s_Switch(self, node: A.Switch) -> None:
        self.check_expr(node.value)
        for case in node.cases:
            self.table.push("block")
            for s in case.body:
                self.check_stmt(s)
            self.table.pop()

    def _s_Return(self, node: A.Return) -> None:
        func = self.current_function
        declared = func.return_type if func is not None else None
        if node.value is None:
            if declared is not None and declared.kind != "void":
                self.warn("W001", f"'{func.name}' should return {declared}", node.loc)
            return
        value = self.check_expr(node.value)
        if declared is not None and declared.kind == "void":
            self.error("E005", f"'{func.name}' is void but returns a value", node.loc)
        elif not T.compatible(declared, value):
            self.error("E006", f"returning {value} from a function returning {declared}", node.loc)

    # -- expressions --------------------------------------------------------

    def check_expr(self, node) -> A.CType | None:
        if node is None:
            return None
        method = getattr(self, f"_e_{type(node).__name__}", None)
        result = method(node) if method is not None else None
        node.type = result
        return result

    def _e_IntLit(self, node) -> A.CType:
        return A.INT

    def _e_CharLit(self, node) -> A.CType:
        return A.CHAR

    def _e_StrLit(self, node) -> A.CType:
        return A.ptr_to(A.CHAR)

    def _e_Ident(self, node: A.Ident) -> A.CType | None:
        symbol = self.table.lookup(node.name)
        if symbol is None:
            self.error("E007", f"use of undeclared identifier '{node.name}'", node.loc)
            return None
        return symbol.type

    def _e_BinaryOp(self, node: A.BinaryOp) -> A.CType | None:
        return T.result_of(node.op, self.check_expr(node.lhs), self.check_expr(node.rhs))

    def _e_UnaryOp(self, node: A.UnaryOp) -> A.CType | None:
        operand = self.check_expr(node.operand)
        if node.op == "&":
            return A.ptr_to(operand or A.INT)
        if node.op == "*":
            if operand is not None and not T.is_pointer_like(operand):
                self.error("E008", f"cannot dereference a value of type {operand}", node.loc)
                return None
            return T.pointee(operand)
        return operand

    def _e_Assign(self, node: A.Assign) -> A.CType | None:
        target = self.check_expr(node.target)
        value = self.check_expr(node.value)
        if not T.compatible(target, value):
            self.error("E009", f"cannot assign {value} to {target}", node.loc)
        return target

    def _e_Index(self, node: A.Index) -> A.CType | None:
        base = self.check_expr(node.base)
        index = self.check_expr(node.index)
        if base is not None and not T.is_pointer_like(base):
            self.error("E010", f"cannot subscript a value of type {base}", node.loc)
        if index is not None and not T.is_arithmetic(index):
            self.error("E011", f"array index has non-integer type {index}", node.loc)
        return T.pointee(base)

    def _e_Member(self, node: A.Member) -> A.CType | None:
        self.check_expr(node.base)
        return None  # struct layouts are not modelled; field types are unknown

    def _e_Cast(self, node: A.Cast) -> A.CType | None:
        self.check_expr(node.expr)
        return node.to

    def _e_Ternary(self, node: A.Ternary) -> A.CType | None:
        self.check_expr(node.cond)
        then = self.check_expr(node.then)
        self.check_expr(node.otherwise)
        return then

    def _e_Call(self, node: A.Call) -> A.CType | None:
        arg_types = [self.check_expr(a) for a in node.args]
        symbol = self.table.lookup(node.func)
        if symbol is None:
            self.warn("W002", f"call to undeclared function '{node.func}'", node.loc)
            return None
        if symbol.kind != "function":
            self.error("E012", f"'{node.func}' is not a function", node.loc)
            return None
        expected = len(symbol.params)
        if not symbol.is_variadic and len(arg_types) != expected:
            self.error(
                "E013",
                f"'{node.func}' expects {expected} argument(s), {len(arg_types)} given",
                node.loc,
            )
        elif symbol.is_variadic and len(arg_types) < expected:
            self.error(
                "E013",
                f"'{node.func}' expects at least {expected} argument(s), "
                f"{len(arg_types)} given",
                node.loc,
            )
        for index, (declared, actual) in enumerate(zip(symbol.params, arg_types)):
            if not T.compatible(declared, actual):
                self.warn(
                    "W003",
                    f"argument {index + 1} of '{node.func}': expected {declared}, got {actual}",
                    node.loc,
                )
        return symbol.type


def check(program: A.Program) -> tuple[list[Diagnostic], SymbolTable]:
    checker = TypeChecker(program)
    return checker.run(), checker.table
