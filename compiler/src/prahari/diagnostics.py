"""Source locations, diagnostics and finding types shared across all phases.

Every IR instruction carries a :class:`Location`; without it the findings panel
cannot navigate and SARIF output cannot be produced.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"

    @property
    def sarif_level(self) -> str:
        return {"error": "error", "warning": "warning", "note": "note"}[self.value]


@dataclass(frozen=True, order=True)
class Location:
    """A half-open source position. ``line`` is 1-based, ``column`` 1-based."""

    file: str = "<unknown>"
    line: int = 0
    column: int = 1

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.file}:{self.line}:{self.column}"

    @classmethod
    def from_coord(cls, coord, fallback: str = "<unknown>") -> "Location":
        """Build a Location from a pycparser ``Coord``."""
        if coord is None:
            return cls(fallback, 0, 1)
        return cls(str(coord.file or fallback), int(coord.line or 0), int(coord.column or 1))


@dataclass
class Diagnostic:
    """A compile-time message produced by the front end or semantic analyser."""

    severity: Severity
    code: str
    message: str
    location: Location

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.location}: {self.severity.value}: [{self.code}] {self.message}"


class PrahariError(Exception):
    """Base class for every error Prahari raises deliberately."""


class UnsupportedConstruct(PrahariError):
    """Raised when the source uses a construct outside the analysed C subset.

    Carrying the construct name lets the evaluation harness produce an exclusion
    log grouped by reason, which the report requires.
    """

    def __init__(self, construct: str, location: Location, detail: str = "") -> None:
        self.construct = construct
        self.location = location
        self.detail = detail
        msg = f"{location}: unsupported construct '{construct}'"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


# --- Security finding types -------------------------------------------------

StepKind = Literal["SOURCE", "PROPAGATE", "SINK"]


@dataclass
class PropagationStep:
    """One hop on a taint path, rendered as a row in the findings panel."""

    kind: StepKind
    location: Location
    value: str
    snippet: str
    explanation: str


@dataclass
class Guard:
    """A conditional that dominates a sink; used to explain path feasibility."""

    location: Location
    condition: str


@dataclass
class TaintPath:
    cwe: str
    source: Location
    sink: Location
    steps: list[PropagationStep] = field(default_factory=list)
    guards: list[Guard] = field(default_factory=list)
    confidence: float | None = None

    @property
    def fingerprint(self) -> str:
        """Stable identity for caching and de-duplication across runs."""
        import hashlib

        parts = [self.cwe] + [f"{s.kind}@{s.location}:{s.value}" for s in self.steps]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


@dataclass
class Finding:
    """An adjudicated (or unadjudicated) security result."""

    path: TaintPath
    rule_id: str
    #: Function containing the sink. Ground-truth scoring in the evaluation
    #: harness is per-function, following the Juliet bad()/good() convention.
    function: str
    title: str
    message: str
    severity: Severity
    missing_control: str = ""
    remediation: str = ""
    exploitable: bool | None = None
    reason: str = ""
    adjudicator: str = "none"

    @property
    def confidence(self) -> float:
        return self.path.confidence if self.path.confidence is not None else 1.0
