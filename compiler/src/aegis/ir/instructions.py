"""Three-address code: the normalised analysis surface.

Every analysis in the project runs on this representation rather than on the
AST. Two properties matter downstream:

* each instruction carries a :class:`Location`, so findings can navigate;
* each instruction exposes ``uses`` and ``defs``, so the generic dataflow
  framework never needs to know what kind of instruction it is looking at.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..diagnostics import Location


# --- Operands ---------------------------------------------------------------


@dataclass(frozen=True)
class Operand:
    pass


@dataclass(frozen=True)
class Const(Operand):
    """An integer or character literal."""

    value: int

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class StrConst(Operand):
    """A string literal. Tracked separately because it is never tainted."""

    value: str

    def __str__(self) -> str:
        text = self.value if len(self.value) <= 24 else self.value[:21] + "..."
        return f'"{text}"'


@dataclass(frozen=True)
class Name(Operand):
    """A variable or compiler-generated temporary, possibly SSA-versioned."""

    name: str
    version: int | None = None

    def __str__(self) -> str:
        return self.name if self.version is None else f"{self.name}.{self.version}"

    @property
    def base(self) -> str:
        """The pre-SSA variable this name refers to."""
        return self.name

    def versioned(self, version: int) -> "Name":
        return Name(self.name, version)


def operand_names(op: Operand | None) -> list[Name]:
    return [op] if isinstance(op, Name) else []


# --- Instructions -----------------------------------------------------------


@dataclass
class Instr:
    loc: Location = field(default_factory=Location, kw_only=True)

    @property
    def uses(self) -> list[Name]:
        """Operands read by this instruction."""
        return []

    @property
    def defs(self) -> list[Name]:
        """Operands written by this instruction."""
        return []

    def replace_uses(self, mapping: dict[str, Name]) -> None:
        """Rewrite read operands in place; used by SSA renaming."""

    def replace_def(self, new: Name) -> None:
        """Rewrite the written operand in place; used by SSA renaming."""

    @property
    def is_terminator(self) -> bool:
        return False


def _sub(op: Operand | None, mapping: dict[str, Name]) -> Operand | None:
    if isinstance(op, Name) and op.name in mapping:
        return mapping[op.name]
    return op


@dataclass
class Assign(Instr):
    """``dst = src``"""

    dst: Name = Name("")
    src: Operand = Const(0)

    @property
    def uses(self) -> list[Name]:
        return operand_names(self.src)

    @property
    def defs(self) -> list[Name]:
        return [self.dst]

    def replace_uses(self, mapping):
        self.src = _sub(self.src, mapping)

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        return f"{self.dst} = {self.src}"


@dataclass
class BinOp(Instr):
    """``dst = lhs op rhs``"""

    dst: Name = Name("")
    op: str = "+"
    lhs: Operand = Const(0)
    rhs: Operand = Const(0)

    @property
    def uses(self):
        return operand_names(self.lhs) + operand_names(self.rhs)

    @property
    def defs(self):
        return [self.dst]

    def replace_uses(self, mapping):
        self.lhs = _sub(self.lhs, mapping)
        self.rhs = _sub(self.rhs, mapping)

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        return f"{self.dst} = {self.lhs} {self.op} {self.rhs}"


@dataclass
class UnOp(Instr):
    """``dst = op src``"""

    dst: Name = Name("")
    op: str = "-"
    src: Operand = Const(0)

    @property
    def uses(self):
        return operand_names(self.src)

    @property
    def defs(self):
        return [self.dst]

    def replace_uses(self, mapping):
        self.src = _sub(self.src, mapping)

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        return f"{self.dst} = {self.op}{self.src}"


@dataclass
class Load(Instr):
    """``dst = *ptr`` -- also models ``base[index]`` and ``base->field``."""

    dst: Name = Name("")
    ptr: Operand = Const(0)
    index: Operand | None = None
    field_name: str = ""

    @property
    def uses(self):
        return operand_names(self.ptr) + operand_names(self.index)

    @property
    def defs(self):
        return [self.dst]

    def replace_uses(self, mapping):
        self.ptr = _sub(self.ptr, mapping)
        self.index = _sub(self.index, mapping)

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        if self.field_name:
            return f"{self.dst} = {self.ptr}.{self.field_name}"
        if self.index is not None:
            return f"{self.dst} = {self.ptr}[{self.index}]"
        return f"{self.dst} = *{self.ptr}"


@dataclass
class Store(Instr):
    """``*ptr = src`` -- also models ``base[index] = src``.

    ``ptr`` is a :class:`Name` rather than a general operand: the analysed
    subset has no pointer arithmetic, so the store target always names a
    variable. Memory is modelled per base variable, field-insensitively.
    """

    ptr: Name = Name("")
    src: Operand = Const(0)
    index: Operand | None = None
    field_name: str = ""

    @property
    def uses(self):
        return operand_names(self.src) + operand_names(self.index) + [self.ptr]

    @property
    def defs(self):
        return []  # memory write, not an SSA definition

    def replace_uses(self, mapping):
        self.src = _sub(self.src, mapping)
        self.index = _sub(self.index, mapping)
        # The pointer written through is itself a *use* of that pointer value,
        # so it must be renamed too; missing this silently desynchronises every
        # analysis keyed on SSA names from the instructions it is reading.
        renamed = _sub(self.ptr, mapping)
        if isinstance(renamed, Name):
            self.ptr = renamed

    def __str__(self) -> str:
        if self.field_name:
            return f"{self.ptr}.{self.field_name} = {self.src}"
        if self.index is not None:
            return f"{self.ptr}[{self.index}] = {self.src}"
        return f"*{self.ptr} = {self.src}"


@dataclass
class AddrOf(Instr):
    """``dst = &src``"""

    dst: Name = Name("")
    src: Name = Name("")

    @property
    def uses(self):
        return [self.src]

    @property
    def defs(self):
        return [self.dst]

    def replace_uses(self, mapping):
        renamed = _sub(self.src, mapping)
        if isinstance(renamed, Name):
            self.src = renamed

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        return f"{self.dst} = &{self.src}"


@dataclass
class Call(Instr):
    """``dst = func(args...)``; ``dst`` is None for a void call."""

    func: str = ""
    args: list[Operand] = field(default_factory=list)
    dst: Name | None = None

    @property
    def uses(self):
        out: list[Name] = []
        for a in self.args:
            out.extend(operand_names(a))
        return out

    @property
    def defs(self):
        return [self.dst] if self.dst is not None else []

    def replace_uses(self, mapping):
        self.args = [_sub(a, mapping) for a in self.args]

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        call = f"{self.func}({', '.join(str(a) for a in self.args)})"
        return f"{self.dst} = {call}" if self.dst is not None else call


@dataclass
class Ret(Instr):
    src: Operand | None = None

    @property
    def uses(self):
        return operand_names(self.src)

    def replace_uses(self, mapping):
        self.src = _sub(self.src, mapping)

    @property
    def is_terminator(self):
        return True

    def __str__(self) -> str:
        return f"ret {self.src}" if self.src is not None else "ret"


@dataclass
class Jump(Instr):
    target: str = ""

    @property
    def is_terminator(self):
        return True

    def __str__(self) -> str:
        return f"goto {self.target}"


@dataclass
class CBranch(Instr):
    cond: Operand = Const(0)
    then_label: str = ""
    else_label: str = ""

    @property
    def uses(self):
        return operand_names(self.cond)

    def replace_uses(self, mapping):
        self.cond = _sub(self.cond, mapping)

    @property
    def is_terminator(self):
        return True

    def __str__(self) -> str:
        return f"if {self.cond} goto {self.then_label} else goto {self.else_label}"


@dataclass
class Label(Instr):
    name: str = ""

    def __str__(self) -> str:
        return f"{self.name}:"


@dataclass
class Phi(Instr):
    """``dst = phi(v1 from B1, v2 from B2, ...)`` -- inserted by SSA construction."""

    dst: Name = Name("")
    incoming: list[tuple[Name, str]] = field(default_factory=list)

    @property
    def uses(self):
        return [n for n, _ in self.incoming]

    @property
    def defs(self):
        return [self.dst]

    def replace_def(self, new):
        self.dst = new

    def __str__(self) -> str:
        parts = ", ".join(f"{v} from {b}" for v, b in self.incoming)
        return f"{self.dst} = phi({parts})"


@dataclass
class Function:
    """A lowered function: a flat instruction list plus its signature."""

    name: str
    params: list[Name] = field(default_factory=list)
    param_types: list[str] = field(default_factory=list)
    return_type: str = "int"
    body: list[Instr] = field(default_factory=list)
    locals: dict[str, str] = field(default_factory=dict)  # name -> type string
    memory_vars: set[str] = field(default_factory=set)  # arrays, structs, address-taken
    loc: Location = field(default_factory=Location)

    def dump(self) -> str:
        head = f"func {self.name}({', '.join(str(p) for p in self.params)}) -> {self.return_type}"
        lines = [head]
        for ins in self.body:
            prefix = "" if isinstance(ins, Label) else "    "
            lines.append(f"{prefix}{ins}" + f"   ; line {ins.loc.line}" * 0)
        return "\n".join(lines)


@dataclass
class Module:
    """All lowered functions in a translation unit."""

    functions: dict[str, Function] = field(default_factory=dict)
    globals: dict[str, str] = field(default_factory=dict)
    externals: set[str] = field(default_factory=set)

    def dump(self) -> str:
        return "\n\n".join(f.dump() for f in self.functions.values())
