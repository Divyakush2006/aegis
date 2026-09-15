"""pycparser ``c_ast`` -> AegisAST lowering.

This is the only module in the project that imports pycparser. Constructs
outside the analysed C subset raise :class:`UnsupportedConstruct` carrying the
construct name, which the evaluation harness aggregates into the exclusion log
the report requires.

Excluded by design (see the scope boundary in the project documents):
``goto``/labels, function pointers, unions, variadic *user* functions, and
inline assembly. Pointer arithmetic parses but is modelled coarsely.
"""
from __future__ import annotations

from pycparser import c_ast, c_parser

from ..diagnostics import Location, UnsupportedConstruct
from . import ast_nodes as A
from .preprocess import PreprocessResult, preprocess

_PRIMITIVES = {
    "int": A.INT,
    "char": A.CHAR,
    "void": A.VOID,
    "float": A.FLOAT,
    "double": A.FLOAT,
    "long": A.INT,
    "short": A.INT,
    "unsigned": A.INT,
    "signed": A.INT,
    "_Bool": A.INT,
    "size_t": A.INT,
    "ssize_t": A.INT,
}


_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a", "b": "\b",
    "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?",
}


def _unescape(text: str) -> str:
    """Decode C escape sequences, including ``\\xHH`` and octal forms."""
    if "\\" not in text:
        return text
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\" or index + 1 >= len(text):
            out.append(char)
            index += 1
            continue
        nxt = text[index + 1]
        if nxt == "x":
            digits = ""
            index += 2
            while index < len(text) and len(digits) < 2 and text[index] in "0123456789abcdefABCDEF":
                digits += text[index]
                index += 1
            out.append(chr(int(digits, 16)) if digits else "x")
            continue
        if nxt in "01234567":
            digits = ""
            index += 1
            while index < len(text) and len(digits) < 3 and text[index] in "01234567":
                digits += text[index]
                index += 1
            out.append(chr(int(digits, 8)))
            continue
        out.append(_ESCAPES.get(nxt, nxt))
        index += 2
    return "".join(out)


def _is_function_pointer(node) -> bool:
    """True for ``int (*f)(int)`` in any of its declarator spellings.

    pycparser nests the declarator as ``PtrDecl -> FuncDecl``, so checking for a
    bare ``FuncDecl`` misses the common case and the exclusion gets logged under
    a vaguer reason than it should.
    """
    while isinstance(node, c_ast.PtrDecl):
        node = node.type
    return isinstance(node, c_ast.FuncDecl)


class Adapter:
    """Lowers a pycparser AST into AegisAST nodes."""

    def __init__(self, filename: str = "<source>", line_offset: int = 0) -> None:
        self.filename = filename
        self.line_offset = line_offset
        self.typedefs: dict[str, A.CType] = {}
        #: Functions skipped because they use constructs outside the subset.
        #: Recorded rather than raised so one unsupported function does not
        #: discard a whole file -- and so the evaluation harness can report an
        #: exclusion log grouped by reason.
        self.exclusions: list[UnsupportedConstruct] = []

    # -- location helper ----------------------------------------------------

    def loc(self, node) -> Location:
        coord = getattr(node, "coord", None)
        if coord is None:
            return Location(self.filename, 0, 1)
        line = int(coord.line or 0) - self.line_offset
        return Location(self.filename, max(line, 0), int(coord.column or 1))

    # -- entry point --------------------------------------------------------

    def lower_program(self, ast: c_ast.FileAST) -> A.Program:
        prog = A.Program(loc=self.loc(ast))
        for ext in ast.ext:
            try:
                if isinstance(ext, c_ast.FuncDef):
                    prog.functions.append(self.lower_funcdef(ext))
                elif isinstance(ext, c_ast.Typedef):
                    self.typedefs[ext.name] = self.lower_type(ext.type)
                elif isinstance(ext, c_ast.Decl):
                    if isinstance(ext.type, c_ast.FuncDecl):
                        prog.functions.append(self.lower_prototype(ext))
                    elif ext.name:
                        prog.globals.append(self.lower_vardecl(ext))
                    # A nameless declaration is a bare type definition
                    # (``struct req { ... };``) and declares no storage.
                elif isinstance(ext, c_ast.Pragma):
                    continue
            except UnsupportedConstruct as exc:
                self.exclusions.append(exc)
        return prog

    # -- declarations -------------------------------------------------------

    def lower_prototype(self, decl: c_ast.Decl) -> A.FuncDecl:
        params, variadic = self.lower_params(decl.type.args)
        return A.FuncDecl(
            name=decl.name,
            return_type=self.lower_type(decl.type.type),
            params=params,
            body=None,
            is_variadic=variadic,
            loc=self.loc(decl),
        )

    def lower_funcdef(self, fd: c_ast.FuncDef) -> A.FuncDecl:
        decl = fd.decl
        if not isinstance(decl.type, c_ast.FuncDecl):
            raise UnsupportedConstruct("function-pointer definition", self.loc(fd))
        params, variadic = self.lower_params(decl.type.args)
        if variadic:
            raise UnsupportedConstruct(
                "variadic user function", self.loc(fd), f"{decl.name} uses ..."
            )
        return A.FuncDecl(
            name=decl.name,
            return_type=self.lower_type(decl.type.type),
            params=params,
            body=self.lower_block(fd.body),
            loc=self.loc(fd),
        )

    def lower_params(self, args) -> tuple[list[A.Param], bool]:
        params: list[A.Param] = []
        variadic = False
        if args is None:
            return params, variadic
        for i, p in enumerate(args.params):
            if isinstance(p, c_ast.EllipsisParam):
                variadic = True
                continue
            if isinstance(p, c_ast.Typename):  # unnamed parameter
                params.append(A.Param(f"$arg{i}", self.lower_type(p.type), self.loc(p)))
                continue
            if _is_function_pointer(p.type):
                raise UnsupportedConstruct("function pointer parameter", self.loc(p))
            name = p.name or f"$arg{i}"
            if name == "void":
                continue
            params.append(A.Param(name, self.lower_type(p.type), self.loc(p)))
        # `f(void)` lowers to a single void param; drop it.
        if len(params) == 1 and params[0].type.kind == "void":
            params = []
        return params, variadic

    def lower_vardecl(self, decl: c_ast.Decl) -> A.VarDecl:
        return A.VarDecl(
            name=decl.name,
            type=self.lower_type(decl.type),
            init=self.lower_init(decl.init),
            loc=self.loc(decl),
        )

    def lower_init(self, init):
        if init is None:
            return None
        if isinstance(init, c_ast.InitList):
            # Aggregate initialisers are modelled by their first element; the
            # analysis is field-insensitive so this loses no taint precision.
            return self.lower_expr(init.exprs[0]) if init.exprs else None
        return self.lower_expr(init)

    # -- types --------------------------------------------------------------

    def lower_type(self, node) -> A.CType:
        if isinstance(node, c_ast.TypeDecl):
            return self.lower_type(node.type)
        if isinstance(node, c_ast.PtrDecl):
            return A.ptr_to(self.lower_type(node.type))
        if isinstance(node, c_ast.ArrayDecl):
            size = None
            if isinstance(node.dim, c_ast.Constant):
                try:
                    size = int(node.dim.value, 0)
                except ValueError:
                    size = None
            return A.array_of(self.lower_type(node.type), size)
        if isinstance(node, c_ast.IdentifierType):
            name = " ".join(node.names)
            if name in self.typedefs:
                return self.typedefs[name]
            for part in reversed(node.names):
                if part in _PRIMITIVES:
                    return _PRIMITIVES[part]
            return A.INT
        if isinstance(node, c_ast.Struct):
            return A.CType("struct", name=node.name or "anon")
        if isinstance(node, c_ast.Union):
            raise UnsupportedConstruct("union", self.loc(node))
        if isinstance(node, c_ast.Enum):
            return A.INT
        if isinstance(node, c_ast.FuncDecl):
            raise UnsupportedConstruct("function pointer type", self.loc(node))
        if isinstance(node, c_ast.Typename):
            return self.lower_type(node.type)
        return A.INT

    # -- statements ---------------------------------------------------------

    def lower_block(self, node) -> A.Block:
        block = A.Block(loc=self.loc(node))
        items = getattr(node, "block_items", None) or []
        for item in items:
            lowered = self.lower_stmt(item)
            if isinstance(lowered, list):
                block.stmts.extend(lowered)
            elif lowered is not None:
                block.stmts.append(lowered)
        return block

    def lower_stmt(self, node):
        if node is None:
            return None
        loc = self.loc(node)

        if isinstance(node, c_ast.Compound):
            return self.lower_block(node)
        if isinstance(node, c_ast.Decl):
            return self.lower_vardecl(node)
        if isinstance(node, c_ast.DeclList):
            return [self.lower_vardecl(d) for d in node.decls]
        if isinstance(node, c_ast.If):
            return A.If(
                cond=self.lower_expr(node.cond),
                then=self.lower_stmt(node.iftrue),
                otherwise=self.lower_stmt(node.iffalse),
                loc=loc,
            )
        if isinstance(node, c_ast.While):
            return A.While(cond=self.lower_expr(node.cond), body=self.lower_stmt(node.stmt), loc=loc)
        if isinstance(node, c_ast.DoWhile):
            return A.While(
                cond=self.lower_expr(node.cond),
                body=self.lower_stmt(node.stmt),
                is_do_while=True,
                loc=loc,
            )
        if isinstance(node, c_ast.For):
            init = self.lower_stmt(node.init) if node.init is not None else None
            if isinstance(init, list):
                init = A.Block(stmts=init, loc=loc)
            return A.For(
                init=init,
                cond=self.lower_expr(node.cond),
                step=self.lower_expr(node.next),
                body=self.lower_stmt(node.stmt),
                loc=loc,
            )
        if isinstance(node, c_ast.Return):
            return A.Return(value=self.lower_expr(node.expr), loc=loc)
        if isinstance(node, c_ast.Break):
            return A.Break(loc=loc)
        if isinstance(node, c_ast.Continue):
            return A.Continue(loc=loc)
        if isinstance(node, c_ast.Switch):
            return self.lower_switch(node)
        if isinstance(node, c_ast.EmptyStatement):
            return None
        if isinstance(node, (c_ast.Goto, c_ast.Label)):
            raise UnsupportedConstruct("goto/label", loc)
        if isinstance(node, c_ast.Pragma):
            return None

        expr = self.lower_expr(node)
        return A.ExprStmt(expr=expr, loc=loc) if expr is not None else None

    def lower_switch(self, node) -> A.Switch:
        sw = A.Switch(value=self.lower_expr(node.cond), loc=self.loc(node))
        body = node.stmt
        items = getattr(body, "block_items", None) or []
        for item in items:
            if isinstance(item, (c_ast.Case, c_ast.Default)):
                value = self.lower_expr(item.expr) if isinstance(item, c_ast.Case) else None
                stmts: list[A.Stmt] = []
                for s in item.stmts or []:
                    low = self.lower_stmt(s)
                    if isinstance(low, list):
                        stmts.extend(low)
                    elif low is not None:
                        stmts.append(low)
                sw.cases.append(A.Case(value=value, body=stmts, loc=self.loc(item)))
        return sw

    # -- expressions --------------------------------------------------------

    def lower_expr(self, node):
        if node is None:
            return None
        loc = self.loc(node)

        if isinstance(node, c_ast.Constant):
            return self.lower_constant(node, loc)
        if isinstance(node, c_ast.ID):
            return A.Ident(name=node.name, loc=loc)
        if isinstance(node, c_ast.BinaryOp):
            return A.BinaryOp(
                op=node.op, lhs=self.lower_expr(node.left), rhs=self.lower_expr(node.right), loc=loc
            )
        if isinstance(node, c_ast.UnaryOp):
            if node.op == "sizeof":
                return A.IntLit(value=0, loc=loc)
            return A.UnaryOp(op=node.op, operand=self.lower_expr(node.expr), loc=loc)
        if isinstance(node, c_ast.Assignment):
            return A.Assign(
                target=self.lower_expr(node.lvalue),
                value=self.lower_expr(node.rvalue),
                op=node.op,
                loc=loc,
            )
        if isinstance(node, c_ast.FuncCall):
            if not isinstance(node.name, c_ast.ID):
                raise UnsupportedConstruct("indirect call", loc)
            args = list(node.args.exprs) if node.args is not None else []
            return A.Call(
                func=node.name.name, args=[self.lower_expr(a) for a in args], loc=loc
            )
        if isinstance(node, c_ast.ArrayRef):
            return A.Index(
                base=self.lower_expr(node.name), index=self.lower_expr(node.subscript), loc=loc
            )
        if isinstance(node, c_ast.StructRef):
            return A.Member(
                base=self.lower_expr(node.name),
                field_name=node.field.name if isinstance(node.field, c_ast.ID) else str(node.field),
                arrow=(node.type == "->"),
                loc=loc,
            )
        if isinstance(node, c_ast.Cast):
            return A.Cast(to=self.lower_type(node.to_type), expr=self.lower_expr(node.expr), loc=loc)
        if isinstance(node, c_ast.TernaryOp):
            return A.Ternary(
                cond=self.lower_expr(node.cond),
                then=self.lower_expr(node.iftrue),
                otherwise=self.lower_expr(node.iffalse),
                loc=loc,
            )
        if isinstance(node, c_ast.ExprList):
            # Comma expression: value is the last operand.
            lowered = [self.lower_expr(e) for e in node.exprs]
            return lowered[-1] if lowered else None
        if isinstance(node, c_ast.InitList):
            return self.lower_init(node)
        if isinstance(node, c_ast.EmptyStatement):
            return None
        raise UnsupportedConstruct(type(node).__name__, loc)

    @staticmethod
    def lower_constant(node, loc: Location):
        kind = node.type
        raw = node.value
        if kind == "string":
            # Escapes must be decoded here, not left for the backend: the string
            # is emitted verbatim into the object file, so an undecoded "\n"
            # would print as a literal backslash and an n.
            return A.StrLit(value=_unescape(raw.strip('"')), loc=loc, type=A.ptr_to(A.CHAR))
        if kind == "char":
            return A.CharLit(value=_unescape(raw.strip("'")), loc=loc, type=A.CHAR)
        try:
            text = raw.rstrip("uUlLfF")
            value = int(text, 0) if kind == "int" else int(float(text))
        except (ValueError, TypeError):
            value = 0
        return A.IntLit(value=value, loc=loc, type=A.INT)


# --- Convenience façade -----------------------------------------------------


def parse_source(
    source: str, filename: str = "<source>", use_cpp: bool = False
) -> tuple[A.Program, PreprocessResult, list[UnsupportedConstruct]]:
    """Preprocess, parse with pycparser, and lower to AegisAST.

    Returns the program, the preprocessing record, and the list of declarations
    excluded because they fall outside the analysed subset.
    """
    pre = preprocess(source, filename, use_cpp=use_cpp)
    ast = c_parser.CParser().parse(pre.text, filename)
    adapter = Adapter(filename=filename, line_offset=pre.prelude_lines)
    program = adapter.lower_program(ast)
    return program, pre, adapter.exclusions


def parse_file(
    path: str, use_cpp: bool = False
) -> tuple[A.Program, PreprocessResult, list[UnsupportedConstruct]]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_source(fh.read(), path, use_cpp=use_cpp)
