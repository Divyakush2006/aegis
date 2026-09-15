"""CWE-134 -- Use of Externally-Controlled Format String.

Detection strategy: an untrusted value reaches the *format* argument position of
a ``printf``-family call. The position differs per function (``printf`` at 0,
``fprintf`` at 1, ``snprintf`` at 2), which is exactly the kind of per-function
knowledge a specification table exists to hold.
"""
from __future__ import annotations

from ...diagnostics import Severity
from .base import Detector


class FormatStringDetector(Detector):
    cwe = "CWE-134"
    name = "Use of Externally-Controlled Format String"
    severity = Severity.ERROR
    precision = "high"
    missing_control = "a constant format string, or escaping of the untrusted value"
    remediation = (
        'Pass the untrusted value as an argument to a constant format: printf("%s", value). '
        "Never pass attacker-influenced data as the format itself -- %n allows memory writes "
        "and %s allows out-of-bounds reads."
    )
    help_uri = "https://cwe.mitre.org/data/definitions/134.html"

    def describe(self, context: dict) -> str:
        return (
            f"Untrusted data is used as the format string of {context['function']}() "
            f"(argument {context['argument_index']}), allowing an attacker to control "
            "format directives and read or write process memory."
        )
