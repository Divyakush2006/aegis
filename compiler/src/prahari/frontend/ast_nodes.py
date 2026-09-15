"""PrahariAST -- the project's own abstract syntax tree.

pycparser supplies ``c_ast``; nothing downstream of this module is allowed to
see it. Every later phase consumes PrahariAST, so if the reused parser is ever
replaced by a hand-written one, only :mod:`prahari.frontend.adapter` changes.

That boundary is also what makes the reused-vs-original split auditable: the
parser is reused, everything from this node set onward is original.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..diagnostics import Location

# --- Types ------------------------------------------------------------------


@dataclass(frozen=True)
class CType:
    """A type in the analysed C subset."""

    kind: str  # "int" | "char" | "void" | "float" | "ptr" | "array" | "struct"
    base: "CType | None" = None
    size: int | None = None  # array extent when statically known
    name: str = ""  # struct tag

    def __str__(self) -> str:
        if self.kind == "ptr":
            return f"{self.base}*"
        if self.kind == "array":
            return f"{self.base}[{self.size if self.size is not None else ''}]"
        if self.kind == "struct":
            return f"struct {self.name}"
        return self.kind

    @property
    def is_scalar(self) -> bool:
        return self.kind in ("int", "char", "float")

    @property
    def is_memory(self) -> bool:
        """True for types whose storage is addressable and not SSA-renameable."""
        return self.kind in ("array", "struct")


INT = CType("int")
CHAR = CType("char")
VOID = CType("void")
FLOAT = CType("float")


def ptr_to(t: CType) -> CType:
    return CType("ptr", base=t)


def array_of(t: CType, n: int | None) -> CType:
    return CType("array", base=t, size=n)


# --- Node hierarchy ---------------------------------------------------------


@dataclass
class Node:
    loc: Location = field(default_factory=Location, kw_only=True)


# Expressions ----------------------------------------------------------------


@dataclass
class Expr(Node):
    type: CType | None = field(default=None, kw_only=True)


@dataclass
class IntLit(Expr):
    value: int = 0


@dataclass
class CharLit(Expr):
    value: str = ""


@dataclass
class StrLit(Expr):
    value: str = ""


@dataclass
class Ident(Expr):
    name: str = ""


@dataclass
class BinaryOp(Expr):
    op: str = "+"
    lhs: Expr | None = None
    rhs: Expr | None = None


@dataclass
class UnaryOp(Expr):
    op: str = "-"  # "-" "!" "~" "*" "&" "++" "--" "p++" "p--"
    operand: Expr | None = None


@dataclass
class Assign(Expr):
    """Assignment is an expression in C; ``op`` carries compound forms."""

    target: Expr | None = None
    value: Expr | None = None
    op: str = "="


@dataclass
class Call(Expr):
    func: str = ""
    args: list[Expr] = field(default_factory=list)


@dataclass
class Index(Expr):
    base: Expr | None = None
    index: Expr | None = None


@dataclass
class Member(Expr):
    base: Expr | None = None
    field_name: str = ""
    arrow: bool = False


@dataclass
class Cast(Expr):
    to: CType | None = None
    expr: Expr | None = None


@dataclass
class Ternary(Expr):
    cond: Expr | None = None
    then: Expr | None = None
    otherwise: Expr | None = None


# Statements -----------------------------------------------------------------


@dataclass
class Stmt(Node):
    pass


@dataclass
class Block(Stmt):
    stmts: list[Stmt] = field(default_factory=list)


@dataclass
class VarDecl(Stmt):
    name: str = ""
    type: CType | None = None
    init: Expr | None = None


@dataclass
class ExprStmt(Stmt):
    expr: Expr | None = None


@dataclass
class If(Stmt):
    cond: Expr | None = None
    then: Stmt | None = None
    otherwise: Stmt | None = None


@dataclass
class While(Stmt):
    cond: Expr | None = None
    body: Stmt | None = None
    is_do_while: bool = False


@dataclass
class For(Stmt):
    init: Stmt | None = None
    cond: Expr | None = None
    step: Expr | None = None
    body: Stmt | None = None


@dataclass
class Return(Stmt):
    value: Expr | None = None


@dataclass
class Break(Stmt):
    pass


@dataclass
class Continue(Stmt):
    pass


@dataclass
class Switch(Stmt):
    value: Expr | None = None
    cases: list["Case"] = field(default_factory=list)


@dataclass
class Case(Stmt):
    value: Expr | None = None  # None == default
    body: list[Stmt] = field(default_factory=list)


# Declarations ---------------------------------------------------------------


@dataclass
class Param:
    name: str
    type: CType
    loc: Location = field(default_factory=Location)


@dataclass
class FuncDecl(Node):
    name: str = ""
    return_type: CType | None = None
    params: list[Param] = field(default_factory=list)
    body: Block | None = None
    is_variadic: bool = False

    @property
    def is_definition(self) -> bool:
        return self.body is not None


@dataclass
class Program(Node):
    functions: list[FuncDecl] = field(default_factory=list)
    globals: list[VarDecl] = field(default_factory=list)

    def function(self, name: str) -> FuncDecl | None:
        for f in self.functions:
            if f.name == name:
                return f
        return None

    @property
    def definitions(self) -> list[FuncDecl]:
        return [f for f in self.functions if f.is_definition]


# --- Visitor ----------------------------------------------------------------


class Visitor:
    """Generic dispatch visitor; subclasses override ``visit_<NodeType>``."""

    def visit(self, node):
        if node is None:
            return None
        method = getattr(self, f"visit_{type(node).__name__}", self.generic_visit)
        return method(node)

    def generic_visit(self, node):
        for value in vars(node).values():
            if isinstance(value, Node):
                self.visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, Node):
                        self.visit(item)
        return None
