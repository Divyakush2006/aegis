"""PrahariAST -> three-address code.

Control flow is made explicit here: ``if``/``while``/``for``/``switch`` and the
short-circuit operators ``&&`` and ``||`` all lower to labels and branches, so
the CFG builder that follows needs no knowledge of source-level constructs.

Scoping is resolved during lowering. A shadowed declaration is given a unique
IR name (``x$1``), which means every later phase can treat a name as a whole-
function identity without consulting a scope tree.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..diagnostics import Location, UnsupportedConstruct
from ..frontend import ast_nodes as A
from . import instructions as I


@dataclass
class _LoopContext:
    break_label: str
    continue_label: str


@dataclass
class _Scope:
    names: dict[str, str] = field(default_factory=dict)


class FunctionLowerer:
    """Lowers one :class:`~prahari.frontend.ast_nodes.FuncDecl` to a flat list."""

    def __init__(self, decl: A.FuncDecl, globals_: dict[str, str]) -> None:
        self.decl = decl
        self.globals = globals_
        self.body: list[I.Instr] = []
        self.scopes: list[_Scope] = [_Scope()]
        self.loops: list[_LoopContext] = []
        self.temp_counter = 0
        self.label_counter = 0
        self.shadow_counter: dict[str, int] = {}
        self.locals: dict[str, str] = {}
        self.memory_vars: set[str] = set()

    # -- name management ----------------------------------------------------

    def fresh_temp(self, loc: Location) -> I.Name:
        self.temp_counter += 1
        name = f"%t{self.temp_counter}"
        self.locals[name] = "int"
        return I.Name(name)

    def fresh_label(self, hint: str = "L") -> str:
        self.label_counter += 1
        return f"{hint}{self.label_counter}"

    def declare(self, source_name: str, type_: A.CType) -> str:
        """Bind a source name in the current scope, renaming on shadowing."""
        ir_name = source_name
        if any(source_name in s.names for s in self.scopes):
            n = self.shadow_counter.get(source_name, 0) + 1
            self.shadow_counter[source_name] = n
            ir_name = f"{source_name}${n}"
        self.scopes[-1].names[source_name] = ir_name
        self.locals[ir_name] = str(type_)
        if type_ is not None and type_.is_memory:
            self.memory_vars.add(ir_name)
        return ir_name

    def resolve(self, source_name: str) -> str:
        for scope in reversed(self.scopes):
            if source_name in scope.names:
                return scope.names[source_name]
        return source_name  # global or extern; left as-is

    def push_scope(self) -> None:
        self.scopes.append(_Scope())

    def pop_scope(self) -> None:
        self.scopes.pop()

    def emit(self, instr: I.Instr) -> I.Instr:
        self.body.append(instr)
        return instr

    def emit_label(self, name: str, loc: Location) -> None:
        self.emit(I.Label(name=name, loc=loc))

    # -- entry point --------------------------------------------------------

    def run(self) -> I.Function:
        params: list[I.Name] = []
        for p in self.decl.params:
            ir_name = self.declare(p.name, p.type)
            params.append(I.Name(ir_name))
            if p.type.kind in ("ptr", "array", "struct"):
                self.memory_vars.add(ir_name)

        entry_loc = self.decl.loc
        self.emit_label("entry", entry_loc)
        if self.decl.body is not None:
            self.lower_stmt(self.decl.body)
        # Guarantee a terminator on the fall-through path.
        if not self.body or not self.body[-1].is_terminator:
            self.emit(I.Ret(src=None, loc=entry_loc))

        return I.Function(
            name=self.decl.name,
            params=params,
            param_types=[str(p.type) for p in self.decl.params],
            return_type=str(self.decl.return_type),
            body=self.body,
            locals=self.locals,
            memory_vars=self.memory_vars,
            loc=self.decl.loc,
        )

    # -- statements ---------------------------------------------------------

    def lower_stmt(self, node) -> None:
        if node is None:
            return
        method = getattr(self, f"_stmt_{type(node).__name__}", None)
        if method is None:
            raise UnsupportedConstruct(type(node).__name__, getattr(node, "loc", Location()))
        method(node)

    def _stmt_Block(self, node: A.Block) -> None:
        self.push_scope()
        for s in node.stmts:
            self.lower_stmt(s)
        self.pop_scope()

    def _stmt_VarDecl(self, node: A.VarDecl) -> None:
        ir_name = self.declare(node.name, node.type)
        if node.init is not None:
            value = self.lower_expr(node.init)
            if node.type is not None and node.type.is_memory:
                self.emit(I.Store(ptr=I.Name(ir_name), src=value, loc=node.loc))
            else:
                self.emit(I.Assign(dst=I.Name(ir_name), src=value, loc=node.loc))

    def _stmt_ExprStmt(self, node: A.ExprStmt) -> None:
        if node.expr is not None:
            self.lower_expr(node.expr, want_value=False)

    def _stmt_If(self, node: A.If) -> None:
        then_l, else_l, end_l = (
            self.fresh_label("if.then"),
            self.fresh_label("if.else"),
            self.fresh_label("if.end"),
        )
        cond = self.lower_expr(node.cond)
        self.emit(
            I.CBranch(
                cond=cond,
                then_label=then_l,
                else_label=else_l if node.otherwise is not None else end_l,
                loc=node.loc,
            )
        )
        self.emit_label(then_l, node.loc)
        self.lower_stmt(node.then)
        if not self._ends_with_terminator():
            self.emit(I.Jump(target=end_l, loc=node.loc))
        if node.otherwise is not None:
            self.emit_label(else_l, node.loc)
            self.lower_stmt(node.otherwise)
            if not self._ends_with_terminator():
                self.emit(I.Jump(target=end_l, loc=node.loc))
        self.emit_label(end_l, node.loc)

    def _stmt_While(self, node: A.While) -> None:
        head, body_l, end_l = (
            self.fresh_label("while.head"),
            self.fresh_label("while.body"),
            self.fresh_label("while.end"),
        )
        self.loops.append(_LoopContext(break_label=end_l, continue_label=head))

        if node.is_do_while:
            self.emit(I.Jump(target=body_l, loc=node.loc))
        self.emit_label(head, node.loc)
        cond = self.lower_expr(node.cond) if node.cond is not None else I.Const(1)
        self.emit(I.CBranch(cond=cond, then_label=body_l, else_label=end_l, loc=node.loc))
        self.emit_label(body_l, node.loc)
        self.lower_stmt(node.body)
        if not self._ends_with_terminator():
            self.emit(I.Jump(target=head, loc=node.loc))
        self.emit_label(end_l, node.loc)
        self.loops.pop()

    def _stmt_For(self, node: A.For) -> None:
        head, body_l, step_l, end_l = (
            self.fresh_label("for.head"),
            self.fresh_label("for.body"),
            self.fresh_label("for.step"),
            self.fresh_label("for.end"),
        )
        self.push_scope()
        if node.init is not None:
            self.lower_stmt(node.init)
        self.loops.append(_LoopContext(break_label=end_l, continue_label=step_l))

        self.emit_label(head, node.loc)
        cond = self.lower_expr(node.cond) if node.cond is not None else I.Const(1)
        self.emit(I.CBranch(cond=cond, then_label=body_l, else_label=end_l, loc=node.loc))
        self.emit_label(body_l, node.loc)
        self.lower_stmt(node.body)
        if not self._ends_with_terminator():
            self.emit(I.Jump(target=step_l, loc=node.loc))
        self.emit_label(step_l, node.loc)
        if node.step is not None:
            self.lower_expr(node.step, want_value=False)
        self.emit(I.Jump(target=head, loc=node.loc))
        self.emit_label(end_l, node.loc)

        self.loops.pop()
        self.pop_scope()

    def _stmt_Switch(self, node: A.Switch) -> None:
        """Lowered to a comparison chain; fallthrough is preserved."""
        value = self.lower_expr(node.value)
        end_l = self.fresh_label("switch.end")
        self.loops.append(_LoopContext(break_label=end_l, continue_label=end_l))

        case_labels = [self.fresh_label("case") for _ in node.cases]
        default_label = end_l
        for idx, case in enumerate(node.cases):
            if case.value is None:
                default_label = case_labels[idx]
                continue
            match_l = case_labels[idx]
            next_l = self.fresh_label("case.test")
            cmp_t = self.fresh_temp(case.loc)
            self.emit(
                I.BinOp(dst=cmp_t, op="==", lhs=value, rhs=self.lower_expr(case.value), loc=case.loc)
            )
            self.emit(
                I.CBranch(cond=cmp_t, then_label=match_l, else_label=next_l, loc=case.loc)
            )
            self.emit_label(next_l, case.loc)
        self.emit(I.Jump(target=default_label, loc=node.loc))

        for idx, case in enumerate(node.cases):
            self.emit_label(case_labels[idx], case.loc)
            self.push_scope()
            for s in case.body:
                self.lower_stmt(s)
            self.pop_scope()
            if not self._ends_with_terminator():
                nxt = case_labels[idx + 1] if idx + 1 < len(node.cases) else end_l
                self.emit(I.Jump(target=nxt, loc=case.loc))
        self.emit_label(end_l, node.loc)
        self.loops.pop()

    def _stmt_Return(self, node: A.Return) -> None:
        value = self.lower_expr(node.value) if node.value is not None else None
        self.emit(I.Ret(src=value, loc=node.loc))

    def _stmt_Break(self, node: A.Break) -> None:
        if not self.loops:
            raise UnsupportedConstruct("break outside loop", node.loc)
        self.emit(I.Jump(target=self.loops[-1].break_label, loc=node.loc))

    def _stmt_Continue(self, node: A.Continue) -> None:
        if not self.loops:
            raise UnsupportedConstruct("continue outside loop", node.loc)
        self.emit(I.Jump(target=self.loops[-1].continue_label, loc=node.loc))

    def _ends_with_terminator(self) -> bool:
        return bool(self.body) and self.body[-1].is_terminator

    # -- expressions --------------------------------------------------------

    def lower_expr(self, node, want_value: bool = True) -> I.Operand:
        if node is None:
            return I.Const(0)
        method = getattr(self, f"_expr_{type(node).__name__}", None)
        if method is None:
            raise UnsupportedConstruct(type(node).__name__, getattr(node, "loc", Location()))
        return method(node, want_value)

    def _expr_IntLit(self, node: A.IntLit, want_value: bool) -> I.Operand:
        return I.Const(node.value)

    def _expr_CharLit(self, node: A.CharLit, want_value: bool) -> I.Operand:
        text = node.value
        return I.Const(ord(text[0]) if text and not text.startswith("\\") else 0)

    def _expr_StrLit(self, node: A.StrLit, want_value: bool) -> I.Operand:
        return I.StrConst(node.value)

    def _expr_Ident(self, node: A.Ident, want_value: bool) -> I.Operand:
        return I.Name(self.resolve(node.name))

    def _expr_Cast(self, node: A.Cast, want_value: bool) -> I.Operand:
        return self.lower_expr(node.expr, want_value)

    def _expr_BinaryOp(self, node: A.BinaryOp, want_value: bool) -> I.Operand:
        if node.op in ("&&", "||"):
            return self._lower_short_circuit(node)
        lhs = self.lower_expr(node.lhs)
        rhs = self.lower_expr(node.rhs)
        dst = self.fresh_temp(node.loc)
        self.emit(I.BinOp(dst=dst, op=node.op, lhs=lhs, rhs=rhs, loc=node.loc))
        return dst

    def _lower_short_circuit(self, node: A.BinaryOp) -> I.Operand:
        """``a && b`` / ``a || b`` -- real branches, so the CFG is faithful."""
        result = self.fresh_temp(node.loc)
        rhs_l, end_l = self.fresh_label("sc.rhs"), self.fresh_label("sc.end")

        lhs = self.lower_expr(node.lhs)
        self.emit(I.Assign(dst=result, src=lhs, loc=node.loc))
        if node.op == "&&":
            self.emit(I.CBranch(cond=result, then_label=rhs_l, else_label=end_l, loc=node.loc))
        else:
            self.emit(I.CBranch(cond=result, then_label=end_l, else_label=rhs_l, loc=node.loc))
        self.emit_label(rhs_l, node.loc)
        rhs = self.lower_expr(node.rhs)
        self.emit(I.Assign(dst=result, src=rhs, loc=node.loc))
        self.emit(I.Jump(target=end_l, loc=node.loc))
        self.emit_label(end_l, node.loc)
        return result

    def _expr_UnaryOp(self, node: A.UnaryOp, want_value: bool) -> I.Operand:
        op = node.op
        if op == "&":
            target = node.operand
            if isinstance(target, A.Ident):
                name = self.resolve(target.name)
                self.memory_vars.add(name)  # address-taken: excluded from SSA
                dst = self.fresh_temp(node.loc)
                self.emit(I.AddrOf(dst=dst, src=I.Name(name), loc=node.loc))
                return dst
            return self.lower_expr(target)
        if op == "*":
            ptr = self.lower_expr(node.operand)
            dst = self.fresh_temp(node.loc)
            self.emit(I.Load(dst=dst, ptr=ptr, loc=node.loc))
            return dst
        if op in ("++", "--", "p++", "p--"):
            return self._lower_incdec(node, op, want_value)
        src = self.lower_expr(node.operand)
        dst = self.fresh_temp(node.loc)
        self.emit(I.UnOp(dst=dst, op=op, src=src, loc=node.loc))
        return dst

    def _lower_incdec(self, node: A.UnaryOp, op: str, want_value: bool) -> I.Operand:
        postfix = op.startswith("p")
        delta = 1 if op.endswith("++") else -1
        target = node.operand
        old = self.lower_expr(target)
        updated = self.fresh_temp(node.loc)
        self.emit(I.BinOp(dst=updated, op="+", lhs=old, rhs=I.Const(delta), loc=node.loc))
        self._store_into(target, updated, node.loc)
        if postfix and want_value:
            keep = self.fresh_temp(node.loc)
            self.emit(I.Assign(dst=keep, src=old, loc=node.loc))
            return keep
        return updated

    def _expr_Assign(self, node: A.Assign, want_value: bool) -> I.Operand:
        value = self.lower_expr(node.value)
        if node.op != "=":  # compound assignment: x op= y
            current = self.lower_expr(node.target)
            folded = self.fresh_temp(node.loc)
            self.emit(
                I.BinOp(dst=folded, op=node.op[:-1], lhs=current, rhs=value, loc=node.loc)
            )
            value = folded
        self._store_into(node.target, value, node.loc)
        return value

    def _store_into(self, target, value: I.Operand, loc: Location) -> None:
        """Emit the write for an lvalue of any supported shape."""
        if isinstance(target, A.Ident):
            name = self.resolve(target.name)
            if name in self.memory_vars:
                self.emit(I.Store(ptr=I.Name(name), src=value, loc=loc))
            else:
                self.emit(I.Assign(dst=I.Name(name), src=value, loc=loc))
            return
        if isinstance(target, A.Index):
            base = self.lower_expr(target.base)
            index = self.lower_expr(target.index)
            base_name = base if isinstance(base, I.Name) else I.Name(str(base))
            self.emit(I.Store(ptr=base_name, src=value, index=index, loc=loc))
            return
        if isinstance(target, A.Member):
            base = self.lower_expr(target.base)
            base_name = base if isinstance(base, I.Name) else I.Name(str(base))
            self.emit(I.Store(ptr=base_name, src=value, field_name=target.field_name, loc=loc))
            return
        if isinstance(target, A.UnaryOp) and target.op == "*":
            ptr = self.lower_expr(target.operand)
            ptr_name = ptr if isinstance(ptr, I.Name) else I.Name(str(ptr))
            self.emit(I.Store(ptr=ptr_name, src=value, loc=loc))
            return
        raise UnsupportedConstruct(f"assignment to {type(target).__name__}", loc)

    def _expr_Index(self, node: A.Index, want_value: bool) -> I.Operand:
        base = self.lower_expr(node.base)
        index = self.lower_expr(node.index)
        dst = self.fresh_temp(node.loc)
        self.emit(I.Load(dst=dst, ptr=base, index=index, loc=node.loc))
        return dst

    def _expr_Member(self, node: A.Member, want_value: bool) -> I.Operand:
        base = self.lower_expr(node.base)
        dst = self.fresh_temp(node.loc)
        self.emit(I.Load(dst=dst, ptr=base, field_name=node.field_name, loc=node.loc))
        return dst

    def _lower_call_arg(self, arg) -> I.Operand:
        """Lower one call argument.

        A struct member passed to a function is passed as the *base object*,
        not as a loaded value. Under the field-insensitive memory model the
        whole struct is one storage location, so ``fgets(r.host, ...)`` must
        write to ``r``; loading the field first would strand the effect on a
        temporary and lose the flow entirely.

        Array subscripts keep value semantics -- ``f(a[i])`` really does pass
        the element -- so only members are treated this way.
        """
        if isinstance(arg, A.Member):
            base = self.lower_expr(arg.base)
            if isinstance(base, I.Name):
                self.memory_vars.add(base.base)
                return base
            return base
        return self.lower_expr(arg)

    def _expr_Call(self, node: A.Call, want_value: bool) -> I.Operand:
        args = [self._lower_call_arg(a) for a in node.args]
        dst = self.fresh_temp(node.loc) if want_value else None
        self.emit(I.Call(func=node.func, args=args, dst=dst, loc=node.loc))
        return dst if dst is not None else I.Const(0)

    def _expr_Ternary(self, node: A.Ternary, want_value: bool) -> I.Operand:
        result = self.fresh_temp(node.loc)
        then_l, else_l, end_l = (
            self.fresh_label("t.then"),
            self.fresh_label("t.else"),
            self.fresh_label("t.end"),
        )
        cond = self.lower_expr(node.cond)
        self.emit(I.CBranch(cond=cond, then_label=then_l, else_label=else_l, loc=node.loc))
        self.emit_label(then_l, node.loc)
        self.emit(I.Assign(dst=result, src=self.lower_expr(node.then), loc=node.loc))
        self.emit(I.Jump(target=end_l, loc=node.loc))
        self.emit_label(else_l, node.loc)
        self.emit(I.Assign(dst=result, src=self.lower_expr(node.otherwise), loc=node.loc))
        self.emit(I.Jump(target=end_l, loc=node.loc))
        self.emit_label(end_l, node.loc)
        return result


def lower_program(
    program: A.Program, exclusions: list[UnsupportedConstruct] | None = None
) -> I.Module:
    """Lower every defined function; prototypes become externals.

    A function using a construct outside the subset is skipped and recorded in
    ``exclusions`` rather than aborting the module, so one unsupported function
    does not cost the analysis of the whole translation unit.
    """
    module = I.Module()
    for g in program.globals:
        module.globals[g.name] = str(g.type)

    for func in program.functions:
        if not func.is_definition:
            module.externals.add(func.name)
            continue
        try:
            module.functions[func.name] = FunctionLowerer(func, module.globals).run()
        except UnsupportedConstruct as exc:
            if exclusions is not None:
                exclusions.append(exc)
            module.externals.add(func.name)

    # A function that is both prototyped and defined is not external. Leaving it
    # in both sets makes code generation emit a declaration with the prototype's
    # placeholder signature and then bind the definition to it, which breaks
    # mutual recursion -- the one case where a forward declaration is required.
    module.externals -= set(module.functions)
    return module
