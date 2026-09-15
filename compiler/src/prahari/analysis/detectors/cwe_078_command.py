"""CWE-78 -- Improper Neutralization of Special Elements used in an OS Command.

Detection strategy: a value derived from an untrusted source reaches the command
argument of ``system``, ``popen`` or an ``exec*`` family call without passing a
sanitizer. The sink specifications live in :mod:`prahari.analysis.specs`; this
module supplies the classification and remediation shown to the user.
"""
from __future__ import annotations

from ...diagnostics import Severity
from .base import Detector


class CommandInjectionDetector(Detector):
    cwe = "CWE-78"
    name = "OS Command Injection"
    severity = Severity.ERROR
    precision = "high"
    missing_control = "input validation or an allowlist before the command is executed"
    remediation = (
        "Replace system()/popen() with execve() and an explicit argument array so the "
        "shell never parses attacker-controlled text. If a shell is unavoidable, validate "
        "the value against a strict allowlist first."
    )
    help_uri = "https://cwe.mitre.org/data/definitions/78.html"

    def describe(self, context: dict) -> str:
        return (
            f"Untrusted data reaches {context['function']}() at argument "
            f"{context['argument_index']} after {context['steps']} propagation step(s) "
            "with no sanitisation on the path, allowing shell command injection."
        )
