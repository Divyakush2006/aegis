"""CWE-416 -- Use After Free (and CWE-415, Double Free).

Detection strategy: the heap state machine observes a read, write or argument
pass of an allocation whose state is ``FREED``. Because allocations are keyed by
allocation site rather than by variable name, freeing through one alias and
using through another is still detected.
"""
from __future__ import annotations

from ...diagnostics import Severity
from .base import Detector


class UseAfterFreeDetector(Detector):
    cwe = "CWE-416"
    name = "Use After Free"
    severity = Severity.ERROR
    precision = "high"
    missing_control = "clearing the pointer at free, or an ownership discipline"
    remediation = (
        "Set the pointer to NULL immediately after free() so a later use faults "
        "deterministically instead of touching reallocated memory, and keep a single "
        "owner responsible for the lifetime."
    )
    help_uri = "https://cwe.mitre.org/data/definitions/416.html"

    def describe(self, context: dict) -> str:
        return f"Freed allocation is used again: {context['detail']}."


class DoubleFreeDetector(Detector):
    cwe = "CWE-415"
    name = "Double Free"
    severity = Severity.ERROR
    precision = "high"
    missing_control = "a guard preventing a second free of the same allocation"
    remediation = "NULL the pointer after free(); free(NULL) is defined and harmless."
    help_uri = "https://cwe.mitre.org/data/definitions/415.html"

    def describe(self, context: dict) -> str:
        return f"The same allocation is released twice: {context['detail']}."
