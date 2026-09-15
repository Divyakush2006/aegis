"""LLVM code generation: three-address IR to executable code.

This is what makes Prahari a compiler rather than an analyser that happens to
parse C. The same IR the security analyses run on is lowered to LLVM IR, which
LLVM turns into object code or JIT-executes. Remove every analysis and a working
compiler remains.

Design notes:

* **Codegen consumes the pre-SSA IR, not the SSA form.** LLVM builds its own SSA
  from ``alloca``/``load``/``store`` via its ``mem2reg`` pass, and handing it
  already-phied IR would mean reconciling two renaming schemes for no gain. The
  analyses keep SSA; the backend takes the same instruction list before it.
* **Every local becomes an ``alloca`` in the entry block.** This is the standard
  Clang-style lowering and the shape ``mem2reg`` expects.
* **Declared-but-undefined functions become external declarations**, so a
  program calling ``printf`` links against libc normally.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from ..diagnostics import PrahariError
from ..ir import instructions as I

try:  # llvmlite is an optional extra: the analyses do not need it.
    import llvmlite.binding as llvm
    import llvmlite.ir as ir

    LLVM_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    LLVM_AVAILABLE = False
    ir = None  # type: ignore[assignment]
    llvm = None  # type: ignore[assignment]

_initialised = False


def ensure_llvm() -> None:
    """Register the native target once per process."""
    global _initialised
    if not LLVM_AVAILABLE:
        raise PrahariError(
            "LLVM code generation requires llvmlite. Install it with: pip install 'prahari-compiler[codegen]'"
        )
    if not _initialised:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            llvm.initialize_native_target()
            llvm.initialize_native_asmprinter()
        _initialised = True


class CodegenError(PrahariError):
    """Raised when a construct cannot be lowered to LLVM IR."""


def _int(bits: int = 32):
    return ir.IntType(bits)


def _llvm_type(name: str):
    """Map an Prahari type string onto an LLVM type."""
    text = (name or "int").strip()
    if text.endswith("*"):
        return _llvm_type(text[:-1]).as_pointer()
    if text.endswith("]"):
        head, _, extent = text[:-1].rpartition("[")
        base = _llvm_type(head)
        try:
            return ir.ArrayType(base, int(extent))
        except ValueError:
            return base.as_pointer()
    if text == "void":
        return ir.VoidType()
    if text == "char":
        return _int(8)
    if text == "float":
        return ir.DoubleType()
    if text.startswith("struct"):
        # Struct layouts are not modelled; an opaque byte pointer is enough to
        # keep signatures well-typed, and the analyses never consult this.
        return _int(8).as_pointer()
    return _int(32)


#: Comparison operators and their LLVM signed predicates.
_COMPARISONS = {"==": "==", "!=": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">="}
_ARITHMETIC = {"+": "add", "-": "sub", "*": "mul", "/": "sdiv", "%": "srem"}
_BITWISE = {"&": "and_", "|": "or_", "^": "xor", "<<": "shl", ">>": "ashr"}


@dataclass
class FunctionEmitter:
    """Lowers one :class:`~prahari.ir.instructions.Function` into an LLVM function."""

    module: "ir.Module"
    function: I.Function
    externals: dict
    globals_: dict
    slots: dict = field(default_factory=dict)
    blocks: dict = field(default_factory=dict)
    builder: object = None
    llvm_function: object = None

    def run(self):
        params = [_llvm_type(t) for t in self.function.param_types]
        return_type = _llvm_type(self.function.return_type)

        # The signature was declared in the emitter's first pass; binding to it
        # here is what makes mutual recursion work, because the callee already
        # exists with its real signature when the caller's body is emitted.
        fn = self.module.globals.get(self.function.name)
        if fn is None or not isinstance(fn, ir.Function):
            fn = ir.Function(
                self.module, ir.FunctionType(return_type, params), name=self.function.name
            )
        self.llvm_function = fn

        entry = fn.append_basic_block("entry")
        self.builder = ir.IRBuilder(entry)

        self._allocate_locals(params)
        self._create_blocks()
        self._emit_body()
        self._terminate_open_blocks(return_type)
        return fn

    # -- setup --------------------------------------------------------------

    def _allocate_locals(self, params) -> None:
        """One alloca per local in the entry block, Clang-style."""
        for name, type_name in self.function.locals.items():
            self.slots[name] = self.builder.alloca(_llvm_type(type_name), name=name.replace("%", "t"))
        for index, param in enumerate(self.function.params):
            slot = self.slots.get(param.base)
            if slot is None:
                slot = self.builder.alloca(params[index], name=param.base)
                self.slots[param.base] = slot
            self.builder.store(self.llvm_function.args[index], slot)

    def _create_blocks(self) -> None:
        for instr in self.function.body:
            if isinstance(instr, I.Label) and instr.name not in self.blocks:
                self.blocks[instr.name] = self.llvm_function.append_basic_block(instr.name)

    def _emit_body(self) -> None:
        for instr in self.function.body:
            if isinstance(instr, I.Label):
                target = self.blocks[instr.name]
                # Falling off the end of a block into a label is an implicit
                # branch; LLVM requires it to be explicit.
                if not self.builder.block.is_terminated:
                    self.builder.branch(target)
                self.builder.position_at_end(target)
                continue
            if self.builder.block.is_terminated:
                continue  # unreachable code after a terminator
            self._emit(instr)

    def _terminate_open_blocks(self, return_type) -> None:
        for block in self.llvm_function.blocks:
            if block.is_terminated:
                continue
            self.builder.position_at_end(block)
            if isinstance(return_type, ir.VoidType):
                self.builder.ret_void()
            else:
                self.builder.ret(ir.Constant(return_type, 0))

    # -- operands -----------------------------------------------------------

    def _slot(self, name: str):
        if name in self.slots:
            return self.slots[name]
        if name in self.globals_:
            return self.globals_[name]
        # A name with no declaration: give it storage so codegen stays total.
        slot = ir.GlobalVariable(self.module, _int(32), name=name)
        slot.linkage = "internal"
        slot.initializer = ir.Constant(_int(32), 0)
        self.globals_[name] = slot
        return slot

    def _value(self, operand):
        """Materialise an operand as an LLVM value."""
        if isinstance(operand, I.Const):
            return ir.Constant(_int(32), operand.value)
        if isinstance(operand, I.StrConst):
            return self._string(operand.value)
        if isinstance(operand, I.Name):
            slot = self._slot(operand.base)
            pointee = slot.type.pointee
            if isinstance(pointee, ir.ArrayType):
                # Array-to-pointer decay, as C requires at every use site.
                zero = ir.Constant(_int(32), 0)
                return self.builder.gep(slot, [zero, zero], inbounds=True)
            return self.builder.load(slot)
        raise CodegenError(f"cannot materialise operand {operand!r}")

    def _string(self, text: str):
        """Intern a string literal as a private global and return a char*."""
        data = bytearray(text.encode("utf-8") + b"\x00")
        name = f".str.{len(self.module.globals)}"
        array = ir.ArrayType(_int(8), len(data))
        global_var = ir.GlobalVariable(self.module, array, name=name)
        global_var.linkage = "private"
        global_var.global_constant = True
        global_var.initializer = ir.Constant(array, data)
        zero = ir.Constant(_int(32), 0)
        return self.builder.gep(global_var, [zero, zero], inbounds=True)

    def _coerce(self, value, target_type):
        """Insert the conversion C would perform implicitly."""
        if value.type == target_type:
            return value
        if isinstance(target_type, ir.IntType) and isinstance(value.type, ir.IntType):
            if value.type.width < target_type.width:
                return self.builder.sext(value, target_type)
            return self.builder.trunc(value, target_type)
        if isinstance(target_type, ir.PointerType) and isinstance(value.type, ir.PointerType):
            return self.builder.bitcast(value, target_type)
        if isinstance(target_type, ir.PointerType) and isinstance(value.type, ir.IntType):
            return self.builder.inttoptr(value, target_type)
        if isinstance(target_type, ir.IntType) and isinstance(value.type, ir.PointerType):
            return self.builder.ptrtoint(value, target_type)
        return value

    def _store(self, name: str, value) -> None:
        slot = self._slot(name)
        self.builder.store(self._coerce(value, slot.type.pointee), slot)

    # -- instruction lowering ------------------------------------------------

    def _emit(self, instr) -> None:
        handler = getattr(self, f"_e_{type(instr).__name__}", None)
        if handler is None:
            raise CodegenError(f"no lowering for {type(instr).__name__}")
        handler(instr)

    def _e_Assign(self, instr: I.Assign) -> None:
        self._store(instr.dst.base, self._value(instr.src))

    def _e_BinOp(self, instr: I.BinOp) -> None:
        lhs, rhs = self._value(instr.lhs), self._value(instr.rhs)
        if isinstance(lhs.type, ir.PointerType) or isinstance(rhs.type, ir.PointerType):
            lhs = self._coerce(lhs, _int(64))
            rhs = self._coerce(rhs, _int(64))
        else:
            width = max(lhs.type.width, rhs.type.width) if isinstance(lhs.type, ir.IntType) else 32
            lhs, rhs = self._coerce(lhs, _int(width)), self._coerce(rhs, _int(width))

        if instr.op in _COMPARISONS:
            result = self.builder.icmp_signed(_COMPARISONS[instr.op], lhs, rhs)
            result = self.builder.zext(result, _int(32))
        elif instr.op in _ARITHMETIC:
            result = getattr(self.builder, _ARITHMETIC[instr.op])(lhs, rhs)
        elif instr.op in _BITWISE:
            result = getattr(self.builder, _BITWISE[instr.op])(lhs, rhs)
        else:
            raise CodegenError(f"unsupported binary operator {instr.op!r}")
        self._store(instr.dst.base, result)

    def _e_UnOp(self, instr: I.UnOp) -> None:
        value = self._value(instr.src)
        if instr.op == "-":
            result = self.builder.neg(value)
        elif instr.op == "!":
            zero = ir.Constant(value.type, 0)
            result = self.builder.zext(self.builder.icmp_signed("==", value, zero), _int(32))
        elif instr.op == "~":
            result = self.builder.not_(value)
        elif instr.op == "+":
            result = value
        else:
            raise CodegenError(f"unsupported unary operator {instr.op!r}")
        self._store(instr.dst.base, result)

    def _e_AddrOf(self, instr: I.AddrOf) -> None:
        slot = self._slot(instr.src.base)
        if isinstance(slot.type.pointee, ir.ArrayType):
            zero = ir.Constant(_int(32), 0)
            slot = self.builder.gep(slot, [zero, zero], inbounds=True)
        self._store(instr.dst.base, slot)

    def _address_of(self, ptr_operand, index_operand):
        """Compute the address denoted by ``base[index]`` or ``*base``."""
        base_name = ptr_operand.base if isinstance(ptr_operand, I.Name) else None
        if base_name is None:
            raise CodegenError("indirect access through a non-name operand")
        slot = self._slot(base_name)
        index = self._value(index_operand) if index_operand is not None else None

        if isinstance(slot.type.pointee, ir.ArrayType):
            zero = ir.Constant(_int(32), 0)
            offset = self._coerce(index, _int(32)) if index is not None else zero
            return self.builder.gep(slot, [zero, offset], inbounds=True)

        pointer = self.builder.load(slot)
        if not isinstance(pointer.type, ir.PointerType):
            pointer = self.builder.inttoptr(pointer, _int(8).as_pointer())
        if index is None:
            return pointer
        return self.builder.gep(pointer, [self._coerce(index, _int(32))], inbounds=True)

    def _e_Load(self, instr: I.Load) -> None:
        if instr.field_name:
            # Struct layouts are not modelled; read the base pointer itself.
            self._store(instr.dst.base, self._value(instr.ptr))
            return
        address = self._address_of(instr.ptr, instr.index)
        self._store(instr.dst.base, self.builder.load(address))

    def _e_Store(self, instr: I.Store) -> None:
        if instr.field_name:
            return  # not modelled; see _e_Load
        address = self._address_of(instr.ptr, instr.index)
        self.builder.store(self._coerce(self._value(instr.src), address.type.pointee), address)

    def _e_Call(self, instr: I.Call) -> None:
        callee = self._callee(instr)
        args = []
        for position, operand in enumerate(instr.args):
            value = self._value(operand)
            if position < len(callee.function_type.args):
                value = self._coerce(value, callee.function_type.args[position])
            args.append(value)
        result = self.builder.call(callee, args)
        if instr.dst is not None and not isinstance(callee.function_type.return_type, ir.VoidType):
            self._store(instr.dst.base, result)

    def _callee(self, instr: I.Call):
        existing = self.module.globals.get(instr.func)
        if existing is not None:
            return existing
        spec = self.externals.get(instr.func)
        if spec is not None:
            return spec
        # Undeclared callee: infer a variadic int(...) signature from the site.
        fn_type = ir.FunctionType(_int(32), [], var_arg=True)
        declared = ir.Function(self.module, fn_type, name=instr.func)
        self.externals[instr.func] = declared
        return declared

    def _e_Ret(self, instr: I.Ret) -> None:
        return_type = self.llvm_function.function_type.return_type
        if isinstance(return_type, ir.VoidType) or instr.src is None:
            self.builder.ret_void() if isinstance(return_type, ir.VoidType) else self.builder.ret(
                ir.Constant(return_type, 0)
            )
            return
        self.builder.ret(self._coerce(self._value(instr.src), return_type))

    def _e_Jump(self, instr: I.Jump) -> None:
        self.builder.branch(self.blocks[instr.target])

    def _e_CBranch(self, instr: I.CBranch) -> None:
        value = self._value(instr.cond)
        zero = ir.Constant(value.type, 0)
        condition = self.builder.icmp_signed("!=", value, zero)
        self.builder.cbranch(condition, self.blocks[instr.then_label], self.blocks[instr.else_label])

    def _e_Phi(self, instr: I.Phi) -> None:
        raise CodegenError(
            "codegen consumes the pre-SSA instruction list; phi nodes are LLVM's job"
        )


class LLVMEmitter:
    """Lowers a whole :class:`~prahari.ir.instructions.Module` to LLVM IR."""

    def __init__(self, module: I.Module, name: str = "prahari") -> None:
        ensure_llvm()
        self.source = module
        self.module = ir.Module(name=name)
        self.module.triple = llvm.get_default_triple()
        self.externals: dict = {}
        self.globals_: dict = {}

    def run(self) -> "ir.Module":
        for name, type_name in self.source.globals.items():
            variable = ir.GlobalVariable(self.module, _llvm_type(type_name), name=name)
            variable.linkage = "internal"
            variable.initializer = ir.Constant(_llvm_type(type_name), None)
            self.globals_[name] = variable

        # Pass 1: declare every *defined* function with its real signature,
        # before any body is emitted. Without this, the first caller of a
        # not-yet-emitted function creates a placeholder declaration and the
        # definition is later bound to that wrong signature -- which is exactly
        # the case mutual recursion always hits.
        for function in self.source.functions.values():
            if function.name in self.module.globals:
                continue
            fn_type = ir.FunctionType(
                _llvm_type(function.return_type),
                [_llvm_type(t) for t in function.param_types],
            )
            ir.Function(self.module, fn_type, name=function.name)

        for name in sorted(self.source.externals):
            if name in self.module.globals:
                continue
            fn_type = ir.FunctionType(_int(32), [], var_arg=True)
            self.externals[name] = ir.Function(self.module, fn_type, name=name)

        # Pass 2: emit bodies.
        for function in self.source.functions.values():
            FunctionEmitter(
                module=self.module,
                function=function,
                externals=self.externals,
                globals_=self.globals_,
            ).run()
        return self.module


# --- Public API -------------------------------------------------------------


def emit_ir(module: I.Module, name: str = "prahari") -> str:
    """Return textual LLVM IR for a lowered module."""
    return str(LLVMEmitter(module, name).run())


def verify(module: I.Module) -> "llvm.ModuleRef":
    """Parse and verify the generated IR, raising on malformed output."""
    ensure_llvm()
    parsed = llvm.parse_assembly(emit_ir(module))
    parsed.verify()
    return parsed


def _target_machine(for_jit: bool = False):
    """Build a target machine appropriate to how the code will be used.

    llvmlite defaults to the ``jitdefault`` code model, which is the *large*
    model: correct for JIT, but it emits absolute 64-bit relocations that a
    system linker rejects when producing an ordinary executable. Object and
    assembly output therefore ask for the small code model and PIC, which is
    what a C toolchain expects.
    """
    target = llvm.Target.from_default_triple()
    if for_jit:
        return target.create_target_machine()
    return target.create_target_machine(codemodel="small", reloc="pic")


def optimise_module(parsed, target_machine, level: int = 2) -> None:
    """Run LLVM's standard optimisation pipeline over a parsed module.

    ``mem2reg`` is the pass that matters here: codegen emits every local as an
    ``alloca``, and this is what promotes them into LLVM's own SSA registers.
    llvmlite replaced the legacy pass manager with the new one, so both spellings
    are attempted -- a missing optimiser must not break code generation.
    """
    if level <= 0:
        return
    try:  # llvmlite >= 0.44: new pass manager
        options = llvm.create_pipeline_tuning_options(speed_level=level)
        builder = llvm.create_pass_builder(target_machine, options)
        builder.getModulePassManager().run(parsed, builder)
        return
    except (AttributeError, TypeError):
        pass
    try:  # llvmlite < 0.44: legacy pass manager
        pass_manager = llvm.create_module_pass_manager()
        legacy = llvm.create_pass_manager_builder()
        legacy.opt_level = level
        legacy.populate(pass_manager)
        pass_manager.run(parsed)
    except AttributeError:  # pragma: no cover - neither API present
        pass


def emit_object(module: I.Module, optimise: int = 2) -> bytes:
    """Compile to a native object file."""
    ensure_llvm()
    parsed = verify(module)
    target_machine = _target_machine()
    optimise_module(parsed, target_machine, optimise)
    return target_machine.emit_object(parsed)


def emit_assembly(module: I.Module) -> str:
    """Compile to native assembly text."""
    ensure_llvm()
    parsed = verify(module)
    target_machine = _target_machine()
    return target_machine.emit_assembly(parsed)


def jit_call(module: I.Module, function: str = "main", *args: int) -> int:
    """JIT-compile the module and call one function. Used by the test suite."""
    import ctypes

    ensure_llvm()
    parsed = verify(module)
    target_machine = _target_machine(for_jit=True)
    with llvm.create_mcjit_compiler(parsed, target_machine) as engine:
        engine.finalize_object()
        address = engine.get_function_address(function)
        if not address:
            raise CodegenError(f"function {function!r} is not defined in the module")
        signature = ctypes.CFUNCTYPE(ctypes.c_int32, *([ctypes.c_int32] * len(args)))
        return int(signature(address)(*args))
