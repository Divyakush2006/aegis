"""Taint specifications for library functions.

Static taint analysis is blind to functions whose bodies it cannot see. The
conventional answer is a hand-written specification table -- which is what this
module is, for the libc surface the analysed subset uses.

The table is deliberately a *data structure*, not code: an inference component
can append to it at runtime (``origin="inferred"``) and the result is cached,
which is the extension point the project documents describe. Nothing else in
the analysis needs to change to accept an inferred specification.

Argument positions are zero-based. ``RETURN`` denotes the call's result.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

RETURN = "RETURN"
Position = int | str


class Role(str, Enum):
    SOURCE = "SOURCE"
    SINK = "SINK"
    PROPAGATOR = "PROPAGATOR"
    SANITIZER = "SANITIZER"
    NEUTRAL = "NEUTRAL"


@dataclass(frozen=True)
class FuncSpec:
    """How taint flows through one external function."""

    name: str
    #: Positions that become tainted purely by calling this function.
    taints: tuple[Position, ...] = ()
    #: ``(from, to)`` pairs: taint on ``from`` reaches ``to``.
    propagates: tuple[tuple[Position, Position], ...] = ()
    #: ``(position, cwe)``: a tainted value here is a vulnerability.
    sinks: tuple[tuple[int, str], ...] = ()
    #: Positions whose taint this function removes.
    sanitizes: tuple[Position, ...] = ()
    #: All arguments from ``vararg_start`` propagate into ``vararg_target``.
    vararg_start: int = 0
    vararg_target: Position | None = None
    #: True when the write has no length bound -- an overflow regardless of taint.
    unbounded_write: int | None = None
    #: Where this specification came from; carried into findings for provenance.
    origin: str = "builtin"
    confidence: float = 1.0
    note: str = ""

    @property
    def role(self) -> Role:
        if self.sinks:
            return Role.SINK
        if self.taints:
            return Role.SOURCE
        if self.sanitizes:
            return Role.SANITIZER
        if self.propagates or self.vararg_target is not None:
            return Role.PROPAGATOR
        return Role.NEUTRAL

    def sink_cwe(self, position: int) -> str | None:
        for pos, cwe in self.sinks:
            if pos == position:
                return cwe
        return None

    def targets_for(self, position: Position) -> list[Position]:
        """Positions that receive taint from ``position``."""
        out = [to for frm, to in self.propagates if frm == position]
        if (
            self.vararg_target is not None
            and isinstance(position, int)
            and position >= self.vararg_start
        ):
            out.append(self.vararg_target)
        return out


def _spec(name: str, **kw) -> FuncSpec:
    return FuncSpec(name=name, **kw)


#: Functions that introduce attacker-controlled data.
SOURCES: tuple[FuncSpec, ...] = (
    _spec("fgets", taints=(0, RETURN), note="reads untrusted input into the buffer"),
    _spec("gets", taints=(0, RETURN), unbounded_write=0, note="unbounded read; unsafe by construction"),
    _spec("scanf", taints=(1, 2, 3, 4), vararg_start=1, note="reads untrusted input into its arguments"),
    _spec("fscanf", taints=(2, 3, 4, 5), vararg_start=2, note="reads untrusted input into its arguments"),
    _spec("read", taints=(1,), note="reads untrusted bytes from a descriptor"),
    _spec("recv", taints=(1,), note="reads untrusted bytes from a socket"),
    _spec("fread", taints=(0,), note="reads untrusted bytes from a stream"),
    _spec("getenv", taints=(RETURN,), note="environment variables are attacker-influenced"),
)

#: Functions that move taint from one argument to another.
PROPAGATORS: tuple[FuncSpec, ...] = (
    _spec("strcpy", propagates=((1, 0), (1, RETURN)), sinks=((1, "CWE-120"),), unbounded_write=0),
    _spec("strcat", propagates=((1, 0), (1, RETURN)), sinks=((1, "CWE-120"),), unbounded_write=0),
    _spec("strncpy", propagates=((1, 0), (1, RETURN))),
    _spec("strncat", propagates=((1, 0), (1, RETURN))),
    _spec("memcpy", propagates=((1, 0), (1, RETURN))),
    _spec("memmove", propagates=((1, 0), (1, RETURN))),
    _spec("strdup", propagates=((0, RETURN),)),
    _spec("strchr", propagates=((0, RETURN),)),
    _spec("strstr", propagates=((0, RETURN),)),
    _spec("atoi", propagates=((0, RETURN),)),
    _spec("atol", propagates=((0, RETURN),)),
    _spec("sscanf", propagates=((0, 2), (0, 3), (0, 4)), vararg_start=2, vararg_target=None),
    _spec(
        "sprintf",
        vararg_start=2,
        vararg_target=0,
        sinks=((1, "CWE-134"),),
        unbounded_write=0,
        note="unbounded formatted write",
    ),
    _spec("snprintf", vararg_start=3, vararg_target=0, sinks=((2, "CWE-134"),)),
)

#: Functions where a tainted argument constitutes a vulnerability.
SINKS: tuple[FuncSpec, ...] = (
    _spec("system", sinks=((0, "CWE-78"),), note="argument is executed by the shell"),
    _spec("popen", sinks=((0, "CWE-78"),), note="argument is executed by the shell"),
    _spec("execl", sinks=((0, "CWE-78"), (1, "CWE-78"))),
    _spec("execlp", sinks=((0, "CWE-78"), (1, "CWE-78"))),
    _spec("execv", sinks=((0, "CWE-78"), (1, "CWE-78"))),
    _spec("execvp", sinks=((0, "CWE-78"), (1, "CWE-78"))),
    _spec("printf", sinks=((0, "CWE-134"),), note="tainted format string"),
    _spec("fprintf", sinks=((1, "CWE-134"),), note="tainted format string"),
    _spec("syslog", sinks=((1, "CWE-134"),), note="tainted format string"),
)

#: Functions with no taint effect, declared explicitly rather than left unknown.
#:
#: The allocator family is tracked by the heap state machine, not by taint. If
#: they were simply absent, they would inflate ``unmodelled_externals`` -- the
#: metric that reports how much of the program the analysis had to guess about
#: -- and make that number describe the specification table's gaps rather than
#: the program's. A metric that measures the wrong thing is worse than none.
NEUTRAL: tuple[FuncSpec, ...] = (
    _spec("malloc", note="tracked by the heap state machine"),
    _spec("calloc", note="tracked by the heap state machine"),
    _spec("realloc", propagates=((0, RETURN),), note="tracked by the heap state machine"),
    _spec("free", note="tracked by the heap state machine"),
    _spec("exit", note="terminates; no taint effect"),
    _spec("abort", note="terminates; no taint effect"),
    _spec("strlen", propagates=((0, RETURN),)),
    _spec("strcmp"),
    _spec("strncmp"),
    _spec("memset"),
    _spec("fopen"),
    _spec("fclose"),
    _spec("puts"),
    _spec("fputs"),
    _spec("fwrite"),
    _spec("pclose"),
    _spec("rand"),
    _spec("srand"),
)

#: Functions that neutralise taint. Extended per-project via ``SpecTable.add``.
SANITIZERS: tuple[FuncSpec, ...] = (
    _spec("aegis_sanitize", sanitizes=(0, RETURN)),
    _spec("validate_input", sanitizes=(0, RETURN)),
    _spec("escape_shell", sanitizes=(0, RETURN)),
)


class SpecTable:
    """Mutable registry of function specifications.

    Detectors contribute their own sink specifications at registration time, and
    an inference component may add entries at runtime. Later additions win, so a
    project-specific sanitizer can override a builtin.
    """

    def __init__(self, specs: list[FuncSpec] | None = None) -> None:
        self._specs: dict[str, FuncSpec] = {}
        for group in (SOURCES, PROPAGATORS, SINKS, NEUTRAL, SANITIZERS):
            for spec in group:
                self.add(spec)
        for spec in specs or []:
            self.add(spec)

    def add(self, spec: FuncSpec) -> None:
        existing = self._specs.get(spec.name)
        if existing is None:
            self._specs[spec.name] = spec
            return
        # Merge rather than replace: a name can be both source and sink.
        self._specs[spec.name] = replace(
            existing,
            taints=tuple(dict.fromkeys(existing.taints + spec.taints)),
            propagates=tuple(dict.fromkeys(existing.propagates + spec.propagates)),
            sinks=tuple(dict.fromkeys(existing.sinks + spec.sinks)),
            sanitizes=tuple(dict.fromkeys(existing.sanitizes + spec.sanitizes)),
            vararg_start=spec.vararg_start or existing.vararg_start,
            vararg_target=(
                spec.vararg_target if spec.vararg_target is not None else existing.vararg_target
            ),
            unbounded_write=(
                spec.unbounded_write
                if spec.unbounded_write is not None
                else existing.unbounded_write
            ),
            origin=spec.origin if spec.origin != "builtin" else existing.origin,
            note=spec.note or existing.note,
        )

    def get(self, name: str) -> FuncSpec | None:
        return self._specs.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return sorted(self._specs)

    @property
    def inferred(self) -> list[FuncSpec]:
        return [s for s in self._specs.values() if s.origin == "inferred"]

    def as_dicts(self) -> list[dict]:
        """Serialisable form, for the spec cache and the report appendix."""
        return [
            {
                "name": s.name,
                "role": s.role.value,
                "taints": list(s.taints),
                "propagates": [list(p) for p in s.propagates],
                "sinks": [list(x) for x in s.sinks],
                "sanitizes": list(s.sanitizes),
                "origin": s.origin,
                "confidence": s.confidence,
            }
            for s in sorted(self._specs.values(), key=lambda s: s.name)
        ]


DEFAULT_SPECS = SpecTable()
