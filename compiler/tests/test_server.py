"""Language server: the compiler's editor-facing surface.

The handlers are exercised directly rather than over a transport. What matters
is that each capability is genuinely derived from a compiler artefact — the
scope-filtering test below is the one that proves the project's claim about
grounded editor assistance, because it asserts that an out-of-scope identifier
is not merely ranked low but absent.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pygls", reason="pygls is not installed")

from lsprotocol import types as lsp  # noqa: E402

from aegis.server import lsp_server as S  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def uri_of(name: str) -> str:
    return (EXAMPLES / name).resolve().as_uri()


@pytest.fixture
def server():
    instance = S.AegisLanguageServer()
    yield instance
    instance.indexes.clear()


class TestUriHandling:
    def test_round_trips_a_local_path(self):
        path = (EXAMPLES / "safe.c").resolve()
        assert Path(S.uri_to_path(path.as_uri())) == path

    def test_strips_the_leading_slash_from_a_drive_letter(self):
        assert S.uri_to_path("file:///C:/tmp/x.c").replace("\\", "/") == "C:/tmp/x.c"


class TestCompilation:
    def test_type_check_only_by_default(self, server):
        index = server.compile(uri_of("cmd_injection.c"))
        assert index is not None
        assert index.findings == []  # security analyses are on-demand

    def test_security_analyses_on_request(self, server):
        index = server.compile(uri_of("cmd_injection.c"), run_security=True)
        assert {"CWE-78", "CWE-120"} <= set(index.findings_by_cwe())

    def test_missing_file_returns_none_rather_than_raising(self, server):
        assert server.compile("file:///definitely/not/here.c") is None

    def test_malformed_source_does_not_kill_the_server(self, server, tmp_path):
        broken = tmp_path / "broken.c"
        broken.write_text("int main( { ; ; ", encoding="utf-8")
        index = server.compile(broken.resolve().as_uri(), run_security=True)
        # Either a diagnostic or None, but never an exception.
        assert index is None or index.errors()


class TestDiagnostics:
    def test_findings_become_diagnostics(self, server):
        index = server.compile(uri_of("cmd_injection.c"), run_security=True)
        diagnostics = S._diagnostics_from(index)
        assert len(diagnostics) == len(index.findings) + len(index.diagnostics)
        assert all(d.source == "aegis" for d in diagnostics)

    def test_path_steps_ride_along_as_related_information(self, server):
        index = server.compile(uri_of("cmd_injection.c"), run_security=True)
        security = [d for d in S._diagnostics_from(index) if d.code.startswith("aegis/")]
        assert security
        assert all(d.related_information for d in security)

    def test_clean_file_has_no_diagnostics(self, server):
        index = server.compile(uri_of("safe.c"), run_security=True)
        assert S._diagnostics_from(index) == []

    def test_severity_is_mapped(self, server):
        index = server.compile(uri_of("memory_bugs.c"), run_security=True)
        levels = {d.severity for d in S._diagnostics_from(index)}
        assert lsp.DiagnosticSeverity.Error in levels


class TestCompletion:
    def _complete(self, server, name: str, line: int):
        uri = uri_of(name)
        server.compile(uri)
        params = lsp.CompletionParams(
            text_document=lsp.TextDocumentIdentifier(uri=uri),
            position=lsp.Position(line=line, character=4),
        )
        return {item.label: item for item in S.completion(server, params).items}

    def test_locals_and_parameters_are_offered(self, server):
        items = self._complete(server, "cmd_injection.c", 16)
        assert {"argc", "argv", "host", "cmd"} <= set(items)

    def test_out_of_scope_identifiers_are_absent_not_merely_ranked_low(self, server):
        """The central claim: the candidate set is computed, not guessed.

        ``user`` and ``out`` are parameters of build_command. Inside main they
        do not exist, so they cannot be suggested — not unlikely, impossible.
        """
        items = self._complete(server, "cmd_injection.c", 16)
        assert "user" not in items and "out" not in items

    def test_functions_are_offered_with_signatures(self, server):
        items = self._complete(server, "cmd_injection.c", 16)
        assert items["build_command"].kind is lsp.CompletionItemKind.Function
        assert "char*" in items["build_command"].detail

    def test_declared_types_are_reported(self, server):
        items = self._complete(server, "cmd_injection.c", 16)
        assert "char[64]" in items["host"].detail

    def test_taint_role_is_surfaced_on_dangerous_functions(self, server):
        items = self._complete(server, "cmd_injection.c", 16)
        assert "SINK" in (items["system"].documentation or "")

    def test_unknown_document_yields_no_items(self, server):
        params = lsp.CompletionParams(
            text_document=lsp.TextDocumentIdentifier(uri="file:///nope.c"),
            position=lsp.Position(line=0, character=0),
        )
        assert S.completion(server, params).items == []


class TestCommands:
    def test_audit_returns_findings_with_full_traces(self, server):
        result = S.audit(server, [uri_of("cmd_injection.c")])
        assert result["findings"]
        command_injection = next(f for f in result["findings"] if f["cwe"] == "CWE-78")
        kinds = [step["kind"] for step in command_injection["steps"]]
        assert kinds[0] == "SOURCE" and kinds[-1] == "SINK"
        assert command_injection["function"] == "main"

    def test_audit_payload_carries_stats_and_revision(self, server):
        result = S.audit(server, [uri_of("cmd_injection.c")])
        assert result["revision"] and "functions" in result["stats"]

    def test_audit_without_a_uri_reports_an_error(self, server):
        assert "error" in S.audit(server, [])

    def test_explain_uses_cfg_and_summary(self, server):
        result = S.explain(server, [uri_of("cmd_injection.c"), "build_command"])
        assert result["blocks"] > 0
        assert "param0 -> param1" in result["taintSummary"]

    def test_explain_unknown_function(self, server):
        assert "error" in S.explain(server, [uri_of("safe.c"), "nope"])

    def test_build_emits_llvm_ir(self, server):
        pytest.importorskip("llvmlite")
        result = S.build(server, [uri_of("safe.c")])
        assert "llvm" in result and "define" in result["llvm"]


class TestSerialisation:
    def test_finding_dict_is_json_safe(self, server):
        import json

        index = server.compile(uri_of("memory_bugs.c"), run_security=True)
        payload = [S.finding_to_dict(f) for f in index.findings]
        assert json.loads(json.dumps(payload))

    def test_step_uris_are_file_urls(self, server):
        index = server.compile(uri_of("cmd_injection.c"), run_security=True)
        payload = S.finding_to_dict(index.findings[-1])
        assert all(step["uri"].startswith("file:") for step in payload["steps"])
