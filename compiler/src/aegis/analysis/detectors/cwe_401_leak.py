"""CWE-401 -- Missing Release of Memory after Effective Lifetime.

Detection strategy: an allocation is still in a live state at function exit and
its ownership never escaped -- it was not returned, not stored into memory the
caller can reach, and not passed to another function.

Those three exclusions matter more than the detection itself. A leak checker
that reports every allocation not freed in the allocating function flags
correct ownership-transferring code, which is the fastest way to make developers
abandon a tool.
"""
from __future__ import annotations

from ...diagnostics import Severity
from .base import Detector


class MemoryLeakDetector(Detector):
    cwe = "CWE-401"
    name = "Missing Release of Memory after Effective Lifetime"
    severity = Severity.WARNING
    precision = "medium"
    missing_control = "a matching free() on every path out of the allocating function"
    remediation = (
        "Free the allocation on every exit path, or transfer ownership explicitly by "
        "returning it and documenting that the caller must free it."
    )
    help_uri = "https://cwe.mitre.org/data/definitions/401.html"

    def describe(self, context: dict) -> str:
        return (
            "Memory allocated here is never released and its ownership never leaves the "
            "function, so the allocation is lost when the function returns."
        )
