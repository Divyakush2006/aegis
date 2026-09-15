"""CWE-120 -- Buffer Copy without Checking Size of Input (classic overflow).

Detection strategy: an untrusted or unbounded-length value reaches the source
argument of a copy primitive that performs no bounds check -- ``strcpy``,
``strcat``, ``sprintf``, ``gets``. The unbounded nature of the destination write
is recorded on the specification (``unbounded_write``), so the detector fires on
the combination of *unbounded destination* and *attacker-influenced source*
rather than on the mere presence of a banned function name.

That distinction is what separates this from a grep for ``strcpy``: a copy of a
compile-time constant into a fixed buffer is not reported.
"""
from __future__ import annotations

from ...diagnostics import Severity
from .base import Detector


class BufferOverflowDetector(Detector):
    cwe = "CWE-120"
    name = "Buffer Copy without Checking Size of Input"
    severity = Severity.ERROR
    precision = "high"
    missing_control = "a length check bounding the copy to the destination's capacity"
    remediation = (
        "Use a bounded primitive (strncpy/snprintf/strlcpy) with the destination's "
        "capacity, and NUL-terminate explicitly. Prefer computing the bound from "
        "sizeof(dst) rather than a literal."
    )
    help_uri = "https://cwe.mitre.org/data/definitions/120.html"

    def describe(self, context: dict) -> str:
        return (
            f"{context['function']}() copies attacker-influenced data into a fixed-size "
            "destination with no length bound, so an input longer than the destination "
            "overflows it."
        )
