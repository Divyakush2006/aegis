"""Type compatibility rules for the analysed C subset.

Deliberately permissive where C itself is permissive (integer promotion, array
decay) and strict only where a mismatch is a genuine defect. A type checker that
reports valid C as an error makes the whole tool untrustworthy.
"""
from __future__ import annotations

from ..frontend import ast_nodes as A

ARITHMETIC = {"int", "char", "float"}


def is_arithmetic(t: A.CType | None) -> bool:
    return t is not None and t.kind in ARITHMETIC


def is_pointer_like(t: A.CType | None) -> bool:
    return t is not None and t.kind in ("ptr", "array")


def decay(t: A.CType | None) -> A.CType | None:
    """Array-to-pointer decay, as applied at call sites and assignments."""
    if t is not None and t.kind == "array":
        return A.ptr_to(t.base or A.INT)
    return t


def pointee(t: A.CType | None) -> A.CType | None:
    return t.base if t is not None and t.kind in ("ptr", "array") else None


def compatible(target: A.CType | None, value: A.CType | None) -> bool:
    """Can ``value`` be assigned to ``target`` without a diagnostic?"""
    if target is None or value is None:
        return True  # unknown type: do not manufacture an error
    target, value = decay(target), decay(value)
    if target.kind == "void" or value.kind == "void":
        return True
    if is_arithmetic(target) and is_arithmetic(value):
        return True  # implicit conversions among int/char/float
    if is_pointer_like(target) and is_pointer_like(value):
        tp, vp = pointee(target), pointee(value)
        if tp is None or vp is None:
            return True
        if tp.kind == "void" or vp.kind == "void":
            return True  # void* converts freely
        return str(tp) == str(vp)
    if is_pointer_like(target) and is_arithmetic(value):
        return True  # NULL and integer-to-pointer casts are idiomatic in C
    if is_arithmetic(target) and is_pointer_like(value):
        return False
    return str(target) == str(value)


def result_of(op: str, lhs: A.CType | None, rhs: A.CType | None) -> A.CType | None:
    """Type of a binary expression."""
    if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
        return A.INT
    if is_pointer_like(lhs):
        return decay(lhs)
    if is_pointer_like(rhs):
        return decay(rhs)
    if lhs is not None and lhs.kind == "float":
        return A.FLOAT
    if rhs is not None and rhs.kind == "float":
        return A.FLOAT
    return A.INT
