"""CWE-476 -- NULL Pointer Dereference.

Detection strategy: the heap state machine reaches a dereference of a pointer
whose state is ``ALLOCATED`` -- meaning an allocator returned it and no path to
this point compared it against NULL. Comparing the pointer to NULL, or using it
directly as a branch condition, moves it to ``CHECKED`` and suppresses the
report, which is why a correctly guarded allocation produces no finding.
"""
from __future__ import annotations

from ...diagnostics import Severity
from .base import Detector


class NullDereferenceDetector(Detector):
    cwe = "CWE-476"
    name = "NULL Pointer Dereference"
    severity = Severity.ERROR
    precision = "medium"
    missing_control = "a NULL check on the allocation result before it is used"
    remediation = (
        "Check the allocator's return value against NULL and handle the failure before "
        "dereferencing. malloc/calloc/realloc all return NULL under memory pressure."
    )
    help_uri = "https://cwe.mitre.org/data/definitions/476.html"

    def describe(self, context: dict) -> str:
        return (
            "A pointer returned by an allocator is dereferenced on a path where it was "
            "never checked against NULL; if the allocation fails the process dereferences "
            "a null pointer and crashes."
        )
