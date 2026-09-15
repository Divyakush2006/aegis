"""Aegis Language Server.

The bridge between the compiler and any editor that speaks LSP. It is the only
component the IDE talks to, which keeps the TypeScript/Python boundary narrow
and stable: the IDE knows about JSON-RPC messages, never about lattices.

Three capabilities, and each one is downstream of a compiler phase rather than
of a heuristic:

* **Diagnostics** come from the type checker and, on demand, the security
  analyses.
* **Completion** is filtered against the symbol table, so an identifier that is
  not in scope at the cursor is not offered. Suggesting an out-of-scope name is
  structurally impossible rather than statistically unlikely -- which is the
  project's argument for grounding editor assistance in compiler artefacts.
* **Hover** reports the declared type from the symbol table, and on a call, the
  function's interprocedural taint summary.

The custom ``aegis/findings`` notification carries full path traces to the
findings panel; LSP diagnostics alone cannot express a multi-step dataflow path.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer

from ..analysis.specs import SpecTable
from ..diagnostics import Finding, Severity
from ..frontend import ast_nodes as A
from ..index import SemanticIndex, build_index

logger = logging.getLogger(__name__)

SERVER_NAME = "aegis"
SERVER_VERSION = "0.1.0"

#: Custom notification carrying full path traces to the findings panel.
FINDINGS_NOTIFICATION = "aegis/findings"
#: Custom notification for audit progress.
STATUS_NOTIFICATION = "aegis/status"

AUDIT_COMMAND = "aegis.audit"
BUILD_COMMAND = "aegis.build"
EXPLAIN_COMMAND = "aegis.explain"
ADJUDICATE_COMMAND = "aegis.adjudicate"
AI_STATUS_COMMAND = "aegis.aiStatus"

_SEVERITY_MAP = {
    Severity.ERROR: lsp.DiagnosticSeverity.Error,
    Severity.WARNING: lsp.DiagnosticSeverity.Warning,
    Severity.NOTE: lsp.DiagnosticSeverity.Information,
}


def uri_to_path(uri: str) -> str:
    """Convert a ``file://`` URI to a local path, Windows drive letters included."""
    parsed = urlparse(uri)
    path = unquote(parsed.path)
    if path.startswith("/") and len(path) > 2 and path[2] == ":":
        path = path[1:]  # /C:/x -> C:/x
    return str(Path(path))


class AegisLanguageServer(LanguageServer):
    """Holds one Semantic Index per open document."""

    def __init__(self) -> None:
        super().__init__(SERVER_NAME, SERVER_VERSION)
        self.indexes: dict[str, SemanticIndex] = {}
        self.specs = SpecTable()

    # -- compilation --------------------------------------------------------

    def compile(self, uri: str, run_security: bool = False) -> SemanticIndex | None:
        """Build (and cache) the Semantic Index for one document.

        ``run_security=False`` is the keystroke path: type checking only, which
        is fast enough to run on every save. The taint and heap analyses are
        reserved for an explicit audit, matching the project's on-demand design.
        """
        path = uri_to_path(uri)
        if not Path(path).exists():
            return None
        try:
            index = build_index(
                [path],
                specs=SpecTable(),
                run_taint=run_security,
                run_memory=run_security,
            )
        except Exception:  # a language server must never die on bad input
            logger.exception("compilation failed for %s", path)
            return None
        self.indexes[uri] = index
        return index

    def index_for(self, uri: str) -> SemanticIndex | None:
        return self.indexes.get(uri) or self.compile(uri)

    def notify(self, method: str, params: Any) -> None:
        """Send a custom notification.

        pygls 2.x moved notification sending onto the protocol object. Wrapping
        it here keeps the handlers readable and means a future rename touches
        one line. Failures are swallowed: a panel update must never take the
        server down.
        """
        try:
            self.protocol.notify(method, params)
        except Exception:  # pragma: no cover - transport-dependent
            logger.debug("could not send %s", method, exc_info=True)


server = AegisLanguageServer()


# --- Diagnostics ------------------------------------------------------------


def _range(line: int, column: int, length: int = 1) -> lsp.Range:
    line0 = max(line - 1, 0)
    col0 = max(column - 1, 0)
    return lsp.Range(
        start=lsp.Position(line=line0, character=col0),
        end=lsp.Position(line=line0, character=col0 + length),
    )


def _diagnostics_from(index: SemanticIndex) -> list[lsp.Diagnostic]:
    out: list[lsp.Diagnostic] = []
    for d in index.diagnostics:
        out.append(
            lsp.Diagnostic(
                range=_range(d.location.line, d.location.column, 8),
                message=d.message,
                severity=_SEVERITY_MAP.get(d.severity, lsp.DiagnosticSeverity.Warning),
                source=SERVER_NAME,
                code=d.code,
            )
        )
    for finding in index.findings:
        sink = finding.path.sink
        related = [
            lsp.DiagnosticRelatedInformation(
                location=lsp.Location(
                    uri=Path(step.location.file).as_uri(),
                    range=_range(step.location.line, step.location.column, 8),
                ),
                message=f"{step.kind}: {step.explanation}",
            )
            for step in finding.path.steps
        ]
        out.append(
            lsp.Diagnostic(
                range=_range(sink.line, sink.column, 12),
                message=f"{finding.title} — {finding.message}",
                severity=_SEVERITY_MAP.get(finding.severity, lsp.DiagnosticSeverity.Warning),
                source=SERVER_NAME,
                code=finding.rule_id,
                related_information=related,
            )
        )
    return out


def _publish(ls: AegisLanguageServer, uri: str, index: SemanticIndex | None) -> None:
    diagnostics = _diagnostics_from(index) if index else []
    try:
        ls.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics)
        )
    except Exception:  # no transport attached (direct handler use, tests)
        logger.debug("could not publish diagnostics for %s", uri, exc_info=True)


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialise a finding with its full path trace for the findings panel."""
    return {
        "ruleId": finding.rule_id,
        "cwe": finding.path.cwe,
        "title": finding.title,
        "message": finding.message,
        "severity": finding.severity.value,
        "function": finding.function,
        "missingControl": finding.missing_control,
        "remediation": finding.remediation,
        "fingerprint": finding.path.fingerprint,
        "confidence": finding.path.confidence,
        "adjudicator": finding.adjudicator,
        "exploitable": finding.exploitable,
        "reason": finding.reason,
        "sink": {
            "uri": Path(finding.path.sink.file).as_uri(),
            "line": finding.path.sink.line,
            "column": finding.path.sink.column,
        },
        "guards": [
            {"condition": g.condition, "line": g.location.line} for g in finding.path.guards
        ],
        "steps": [
            {
                "kind": step.kind,
                "uri": Path(step.location.file).as_uri(),
                "line": step.location.line,
                "column": step.location.column,
                "value": step.value,
                "snippet": step.snippet,
                "explanation": step.explanation,
            }
            for step in finding.path.steps
        ],
    }


def _audit_payload(uri: str, index: SemanticIndex) -> dict[str, Any]:
    """The message the findings panel consumes, for both audit and adjudicate."""
    return {
        "uri": uri,
        "revision": index.revision,
        "stats": index.stats,
        "findings": [finding_to_dict(f) for f in index.findings],
        "exclusions": [e.as_dict() for e in index.exclusions],
        "adjudication": index.stats.get("adjudication"),
    }


# --- Lifecycle --------------------------------------------------------------


@server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: AegisLanguageServer, params: lsp.DidOpenTextDocumentParams) -> None:
    _publish(ls, params.text_document.uri, ls.compile(params.text_document.uri))


@server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
def did_save(ls: AegisLanguageServer, params: lsp.DidSaveTextDocumentParams) -> None:
    _publish(ls, params.text_document.uri, ls.compile(params.text_document.uri))


@server.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
def did_close(ls: AegisLanguageServer, params: lsp.DidCloseTextDocumentParams) -> None:
    ls.indexes.pop(params.text_document.uri, None)
    _publish(ls, params.text_document.uri, None)


# --- Completion: filtered against the symbol table --------------------------


def _enclosing_function(program: A.Program | None, line: int) -> A.FuncDecl | None:
    """The function whose declaration most closely precedes ``line``."""
    if program is None:
        return None
    candidates = [f for f in program.definitions if f.loc.line <= line]
    return max(candidates, key=lambda f: f.loc.line) if candidates else None


@server.feature(
    lsp.TEXT_DOCUMENT_COMPLETION,
    lsp.CompletionOptions(trigger_characters=[".", ">", "("]),
)
def completion(
    ls: AegisLanguageServer, params: lsp.CompletionParams
) -> lsp.CompletionList:
    """Offer only identifiers the symbol table says are in scope.

    This is the editor-facing consequence of having a real front end: the
    candidate set is computed, not guessed, so an out-of-scope name cannot be
    suggested at all.
    """
    index = ls.index_for(params.text_document.uri)
    if index is None or index.program is None:
        return lsp.CompletionList(is_incomplete=False, items=[])

    line = params.position.line + 1
    items: list[lsp.CompletionItem] = []
    seen: set[str] = set()

    enclosing = _enclosing_function(index.program, line)
    if enclosing is not None:
        for param in enclosing.params:
            seen.add(param.name)
            items.append(
                lsp.CompletionItem(
                    label=param.name,
                    kind=lsp.CompletionItemKind.Variable,
                    detail=f"{param.type} (parameter of {enclosing.name})",
                    sort_text=f"0{param.name}",
                )
            )
        for local in _locals_of(enclosing):
            if local.name in seen:
                continue
            seen.add(local.name)
            items.append(
                lsp.CompletionItem(
                    label=local.name,
                    kind=lsp.CompletionItemKind.Variable,
                    detail=f"{local.type} (local)",
                    sort_text=f"1{local.name}",
                )
            )

    for global_var in index.program.globals:
        if global_var.name in seen or not global_var.name:
            continue
        seen.add(global_var.name)
        items.append(
            lsp.CompletionItem(
                label=global_var.name,
                kind=lsp.CompletionItemKind.Variable,
                detail=f"{global_var.type} (global)",
                sort_text=f"2{global_var.name}",
            )
        )

    for function in index.program.functions:
        if function.name in seen or not function.name:
            continue
        seen.add(function.name)
        signature = ", ".join(str(p.type) for p in function.params)
        spec = index.specs.get(function.name)
        detail = f"{function.return_type} {function.name}({signature})"
        documentation = None
        if spec is not None and spec.role.value != "NEUTRAL":
            documentation = f"Taint role: {spec.role.value}. {spec.note}".strip()
        items.append(
            lsp.CompletionItem(
                label=function.name,
                kind=lsp.CompletionItemKind.Function,
                detail=detail,
                documentation=documentation,
                insert_text=f"{function.name}(",
                sort_text=f"3{function.name}",
            )
        )

    return lsp.CompletionList(is_incomplete=False, items=items)


def _locals_of(function: A.FuncDecl) -> list[A.VarDecl]:
    """Every variable declared anywhere in a function body."""
    found: list[A.VarDecl] = []

    def walk(node) -> None:
        if node is None:
            return
        if isinstance(node, A.VarDecl):
            found.append(node)
        for value in vars(node).values():
            if isinstance(value, A.Node):
                walk(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, A.Node):
                        walk(item)

    walk(function.body)
    return found


# --- Hover ------------------------------------------------------------------


@server.feature(lsp.TEXT_DOCUMENT_HOVER)
def hover(ls: AegisLanguageServer, params: lsp.HoverParams) -> lsp.Hover | None:
    index = ls.index_for(params.text_document.uri)
    if index is None or index.program is None:
        return None

    word = _word_at(ls, params)
    if not word:
        return None

    lines: list[str] = []
    function = index.program.function(word)
    if function is not None:
        signature = ", ".join(f"{p.type} {p.name}" for p in function.params)
        lines.append(f"```c\n{function.return_type} {word}({signature})\n```")
        summary = index.summaries.get(word)
        if summary is not None:
            lines.append(f"**Taint summary** — {summary.describe()}")

    spec = index.specs.get(word)
    if spec is not None and spec.role.value != "NEUTRAL":
        lines.append(f"**Taint role** — `{spec.role.value}`" + (f". {spec.note}" if spec.note else ""))

    enclosing = _enclosing_function(index.program, params.position.line + 1)
    if enclosing is not None:
        for declaration in list(enclosing.params) + _locals_of(enclosing):
            if declaration.name == word:
                lines.append(f"```c\n{declaration.type} {word}\n```")
                break

    if not lines:
        return None
    return lsp.Hover(contents=lsp.MarkupContent(kind=lsp.MarkupKind.Markdown, value="\n\n".join(lines)))


def _word_at(ls: AegisLanguageServer, params) -> str:
    try:
        document = ls.workspace.get_text_document(params.text_document.uri)
        line = document.lines[params.position.line]
    except (IndexError, KeyError, AttributeError):
        return ""
    start = end = params.position.character
    while start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
        start -= 1
    while end < len(line) and (line[end].isalnum() or line[end] == "_"):
        end += 1
    return line[start:end]


# --- Commands ---------------------------------------------------------------


@server.command(AUDIT_COMMAND)
def audit(ls: AegisLanguageServer, *args: Any) -> dict:
    """Run the full security pipeline and push results to the findings panel."""
    uri = _first_uri(args)
    if uri is None:
        return {"error": "no document specified"}

    ls.notify(STATUS_NOTIFICATION, {"state": "running", "uri": uri})
    index = ls.compile(uri, run_security=True)
    if index is None:
        ls.notify(STATUS_NOTIFICATION, {"state": "failed", "uri": uri})
        return {"error": "compilation failed"}

    payload = _audit_payload(uri, index)
    _publish(ls, uri, index)
    ls.notify(FINDINGS_NOTIFICATION, payload)
    ls.notify(
        STATUS_NOTIFICATION,
        {"state": "done", "uri": uri, "findings": len(index.findings)},
    )
    return payload


@server.command(EXPLAIN_COMMAND)
def explain(ls: AegisLanguageServer, *args: Any) -> dict:
    """Explain a function using compiler artefacts: CFG shape and taint summary."""
    uri = _first_uri(args)
    name = _first_name(args)
    # Summaries are a product of the interprocedural pass, so an explanation
    # needs the full pipeline rather than the fast type-check path.
    index = ls.compile(uri, run_security=True) if uri else None
    if index is None or name is None:
        return {"error": "usage: aegis.explain <uri> <function>"}

    cfg = index.cfgs.get(name)
    if cfg is None:
        return {"error": f"no function named {name!r}"}

    summary = index.summaries.get(name)
    callees = sorted(index.callgraph.graph.successors(name)) if index.callgraph else []
    return {
        "function": name,
        "blocks": len(cfg),
        "instructions": sum(len(b.all_instrs) for b in cfg),
        "parameters": [str(p) for p in cfg.function.params],
        "returnType": cfg.function.return_type,
        "callees": callees,
        "taintSummary": summary.describe() if summary else "no taint flow",
    }


@server.command(ADJUDICATE_COMMAND)
def adjudicate(ls: AegisLanguageServer, *args: Any) -> dict:
    """Audit, then review each finding through the configured model.

    Separate from ``aegis.audit`` on purpose. An audit is free, local and runs
    on every request; adjudication costs a network round trip per finding, so
    it is something the user asks for rather than something that happens to
    them. With no key configured this returns the audit unchanged and says so
    in ``adjudication.model``.
    """
    uri = _first_uri(args)
    if uri is None:
        return {"error": "no document specified"}

    ls.notify(STATUS_NOTIFICATION, {"state": "running", "uri": uri, "phase": "adjudicating"})
    index = ls.compile(uri, run_security=True)
    if index is None:
        ls.notify(STATUS_NOTIFICATION, {"state": "failed", "uri": uri})
        return {"error": "compilation failed"}

    try:
        from ..ai.adjudicator import Adjudicator
        from ..ai.config import load_config
        from ..ai.gateway import build_gateway

        # The IDE is the interactive use case: a developer is waiting, so it
        # resolves the model chosen for time-to-verdict rather than depth.
        config = load_config(role="interactive")
        gateway = build_gateway(config)
        reviewer = Adjudicator(gateway, redact_paths=config.redact_paths)
        reviewer.run(index)
        index.stats["adjudication"] = reviewer.stats.as_dict()
        index.stats["adjudication"]["enabled"] = reviewer.enabled
        index.stats["adjudication"]["role"] = "interactive"
        index.stats["adjudication"]["reason"] = getattr(gateway, "reason", "")
    except Exception as exc:  # the audit is still valid without a second opinion
        logger.exception("adjudication failed")
        index.stats["adjudication"] = {"enabled": False, "error": str(exc)}

    payload = _audit_payload(uri, index)
    _publish(ls, uri, index)
    ls.notify(FINDINGS_NOTIFICATION, payload)
    ls.notify(
        STATUS_NOTIFICATION,
        {"state": "done", "uri": uri, "findings": len(index.findings)},
    )
    return payload


@server.command(AI_STATUS_COMMAND)
def ai_status(ls: AegisLanguageServer, *args: Any) -> dict:
    """Report whether adjudication is configured, without disclosing the key."""
    try:
        from ..ai.config import load_config

        return load_config().describe()
    except Exception as exc:
        return {"configured": False, "error": str(exc)}


@server.command(BUILD_COMMAND)
def build(ls: AegisLanguageServer, *args: Any) -> dict:
    """Generate LLVM IR for the document, so the IDE can show the backend output."""
    uri = _first_uri(args)
    index = ls.index_for(uri) if uri else None
    if index is None:
        return {"error": "compilation failed"}
    try:
        from ..codegen.llvm_emitter import emit_ir

        return {"uri": uri, "llvm": emit_ir(index.module)}
    except Exception as exc:
        return {"error": str(exc)}


def _flatten(args) -> list:
    """Flatten one level of nesting in command arguments.

    pygls unpacks ``ExecuteCommandParams.arguments`` into positional
    parameters, but a caller invoking the handler directly (the tests, or
    another Python component) naturally passes the list itself. Accepting both
    shapes keeps one code path for both callers.
    """
    out: list = []
    for arg in args or ():
        if isinstance(arg, (list, tuple)):
            out.extend(_flatten(arg))
        else:
            out.append(arg)
    return out


def _first_uri(args) -> str | None:
    """Find a document URI among command arguments.

    Clients differ: some send a bare string, some wrap it in an object with a
    ``uri`` field. Handling both keeps the command usable from Theia, from a
    plain LSP client, and from a direct call.
    """
    for arg in _flatten(args):
        if isinstance(arg, str) and arg.startswith("file:"):
            return arg
        if isinstance(arg, dict) and isinstance(arg.get("uri"), str):
            return arg["uri"]
    return None


def _first_name(args) -> str | None:
    """The first plain string argument that is not a URI -- a function name."""
    for arg in _flatten(args):
        if isinstance(arg, str) and not arg.startswith("file:"):
            return arg
    return None


def main() -> None:
    """Entry point: serve over stdio, which is what Theia's client expects."""
    logging.basicConfig(level=logging.WARNING)
    server.start_io()


if __name__ == "__main__":  # pragma: no cover
    main()
