"""Scoped symbol table.

A scope tree rather than a flat map, because the editor integration needs to
answer "what identifiers are in scope at this position" -- the query that lets a
completion list be filtered against real program structure instead of guessed
from surrounding text.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..diagnostics import Location
from ..frontend import ast_nodes as A


@dataclass
class Symbol:
    name: str
    type: A.CType
    kind: str  # "variable" | "parameter" | "function" | "global"
    location: Location
    is_defined: bool = True
    params: list[A.CType] = field(default_factory=list)
    is_variadic: bool = False

    def __str__(self) -> str:
        if self.kind == "function":
            args = ", ".join(str(p) for p in self.params)
            return f"{self.type} {self.name}({args})"
        return f"{self.type} {self.name}"


@dataclass
class Scope:
    """One lexical scope; ``parent`` is None for the global scope."""

    parent: "Scope | None" = None
    kind: str = "block"
    symbols: dict[str, Symbol] = field(default_factory=dict)
    children: list["Scope"] = field(default_factory=list)

    def declare(self, symbol: Symbol) -> Symbol | None:
        """Add a symbol. Returns the existing one if this is a redeclaration."""
        existing = self.symbols.get(symbol.name)
        if existing is not None:
            return existing
        self.symbols[symbol.name] = symbol
        return None

    def lookup(self, name: str) -> Symbol | None:
        scope: Scope | None = self
        while scope is not None:
            found = scope.symbols.get(name)
            if found is not None:
                return found
            scope = scope.parent
        return None

    def lookup_local(self, name: str) -> Symbol | None:
        return self.symbols.get(name)

    def push(self, kind: str = "block") -> "Scope":
        child = Scope(parent=self, kind=kind)
        self.children.append(child)
        return child

    def visible(self) -> list[Symbol]:
        """Every symbol visible here, innermost declaration winning."""
        out: dict[str, Symbol] = {}
        chain: list[Scope] = []
        scope: Scope | None = self
        while scope is not None:
            chain.append(scope)
            scope = scope.parent
        for s in reversed(chain):
            out.update(s.symbols)
        return sorted(out.values(), key=lambda s: s.name)


class SymbolTable:
    """The scope tree for a whole program."""

    def __init__(self) -> None:
        self.global_scope = Scope(kind="global")
        self.current = self.global_scope
        self.function_scopes: dict[str, Scope] = {}

    def push(self, kind: str = "block") -> Scope:
        self.current = self.current.push(kind)
        return self.current

    def pop(self) -> None:
        if self.current.parent is not None:
            self.current = self.current.parent

    def declare(self, symbol: Symbol) -> Symbol | None:
        return self.current.declare(symbol)

    def lookup(self, name: str) -> Symbol | None:
        return self.current.lookup(name)

    def functions(self) -> list[Symbol]:
        return [s for s in self.global_scope.symbols.values() if s.kind == "function"]
