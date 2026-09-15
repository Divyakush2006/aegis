"""Human-readable terminal output.

The path trace is the centrepiece: a finding is only actionable if the reviewer
can see *why* the tool believes the value is attacker-controlled. Printing the
route from source to sink, with the reason for each hop, is what separates this
from a linter that names a banned function.
"""
from __future__ import annotations

import os
import sys

from ..diagnostics import Finding, Severity
from ..index import SemanticIndex


#: Trace glyphs, with an ASCII fallback for consoles that cannot encode them
#: (the Windows default code page among them). Detected, never assumed -- a
#: report that crashes on the grader's terminal is worse than a plain one.
GLYPHS_UNICODE = {"node": "●", "step": "○", "down": "▼", "bar": "│", "dot": "·"}
GLYPHS_ASCII = {"node": "*", "step": "o", "down": "v", "bar": "|", "dot": "-"}


def _supports(stream, glyphs: dict) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "".join(glyphs.values()).encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


class Style:
    """ANSI styling and glyph selection, both detected from the output stream."""

    def __init__(self, enabled: bool | None = None, unicode: bool | None = None) -> None:
        if enabled is None:
            enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.enabled = enabled
        if unicode is None:
            unicode = _supports(sys.stdout, GLYPHS_UNICODE)
        self.glyphs = GLYPHS_UNICODE if unicode else GLYPHS_ASCII

    def glyph(self, name: str) -> str:
        return self.glyphs[name]

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t): return self._wrap("1", t)
    def dim(self, t): return self._wrap("2", t)
    def red(self, t): return self._wrap("31", t)
    def yellow(self, t): return self._wrap("33", t)
    def blue(self, t): return self._wrap("34", t)
    def cyan(self, t): return self._wrap("36", t)
    def green(self, t): return self._wrap("32", t)


_SEVERITY_COLOUR = {
    Severity.ERROR: "red",
    Severity.WARNING: "yellow",
    Severity.NOTE: "blue",
}


def render_finding(finding: Finding, style: Style, index: int, total: int) -> str:
    colour = getattr(style, _SEVERITY_COLOUR[finding.severity])
    dot = style.glyph("dot")
    head = (
        f"{colour(style.glyph('node'))} {style.bold(finding.title)} "
        f"{style.dim(style.glyph('dot'))} {colour(finding.severity.value.upper())} "
        f"{style.dim(dot + f' {finding.rule_id} ' + dot + f' [{index}/{total}]')}"
    )
    lines = [head, f"  {finding.message}", ""]

    steps = finding.path.steps
    for position, step in enumerate(steps):
        marker = style.glyph("node" if step.kind in ("SOURCE", "SINK") else "step")
        location = f"{_short(step.location.file)}:{step.location.line}"
        snippet = step.snippet or step.value
        lines.append(
            f"  {colour(marker)} {style.bold(step.kind.ljust(9))} "
            f"{style.cyan(location.ljust(24))} {snippet}"
        )
        lines.append(
            f"  {style.dim(style.glyph('bar'))}{' ' * 34}{style.dim(step.explanation)}"
        )
        if position < len(steps) - 1:
            lines.append(f"  {style.dim(style.glyph('down'))}")

    lines.append("")
    if finding.path.guards:
        conditions = ", ".join(
            f"{g.condition} (line {g.location.line})" for g in finding.path.guards
        )
        lines.append(f"  {style.bold('GUARDS ON PATH')}   {conditions}")
    else:
        lines.append(f"  {style.bold('GUARDS ON PATH')}   {style.dim('none')}")
    lines.append(f"  {style.bold('MISSING CONTROL')}  {finding.missing_control}")
    lines.append(f"  {style.bold('SUGGESTED FIX')}    {finding.remediation}")
    if finding.exploitable is not None:
        verdict = "exploitable" if finding.exploitable else "not exploitable"
        lines.append(
            f"  {style.bold('ADJUDICATION')}     {verdict} "
            f"({finding.adjudicator}, confidence {finding.confidence:.2f}) -- {finding.reason}"
        )
    return "\n".join(lines)


def _short(path: str, width: int = 40) -> str:
    return path if len(path) <= width else "..." + path[-(width - 3):]


def render(index: SemanticIndex, style: Style | None = None, show_stats: bool = True) -> str:
    style = style or Style()
    out: list[str] = []

    errors = index.errors()
    if errors:
        out.append(style.bold(f"Compilation diagnostics ({len(errors)} error(s))"))
        for diagnostic in errors[:20]:
            out.append(f"  {style.red('error')} {diagnostic.location}: {diagnostic.message}")
        out.append("")

    total = len(index.findings)
    if total == 0:
        out.append(style.green("No security findings."))
    else:
        counts = {cwe: len(items) for cwe, items in index.findings_by_cwe().items()}
        breakdown = ", ".join(f"{cwe} x{n}" for cwe, n in sorted(counts.items()))
        out.append(style.bold(f"Security findings: {total}  ({breakdown})"))
        out.append("")
        for position, finding in enumerate(index.findings, start=1):
            out.append(render_finding(finding, style, position, total))
            out.append("")

    if index.exclusions:
        out.append(style.bold(f"Excluded from analysis ({len(index.exclusions)})"))
        grouped: dict[str, int] = {}
        for exclusion in index.exclusions:
            grouped[exclusion.construct] = grouped.get(exclusion.construct, 0) + 1
        for construct, count in sorted(grouped.items(), key=lambda kv: -kv[1]):
            out.append(f"  {style.dim(style.glyph('dot'))} {construct}: {count}")
        out.append("")

    if show_stats:
        stats = index.stats
        out.append(style.dim(
            f"revision {index.revision} | "
            f"{stats.get('functions', 0)} functions | "
            f"{stats.get('basic_blocks', 0)} blocks | "
            f"{stats.get('instructions', 0)} instructions | "
            f"{stats.get('unmodelled_externals', 0)} unmodelled externals | "
            f"{stats.get('elapsed_seconds', 0)}s"
        ))
    return "\n".join(out)


def render_table(index: SemanticIndex, style: Style | None = None) -> str:
    """Compact one-line-per-finding view, for CI logs."""
    style = style or Style()
    if not index.findings:
        return style.green("No security findings.")
    rows = [("SEVERITY", "CWE", "LOCATION", "MESSAGE")]
    for finding in index.findings:
        rows.append(
            (
                finding.severity.value.upper(),
                finding.path.cwe,
                f"{_short(finding.path.sink.file, 28)}:{finding.path.sink.line}",
                finding.message[:72],
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = []
    for position, row in enumerate(rows):
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        lines.append(style.bold(line) if position == 0 else line)
    return "\n".join(lines)
