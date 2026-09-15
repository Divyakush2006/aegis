"""End-to-end: the Semantic Index, SARIF output, slicing and the CLI."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.ai.adjudicator import Adjudicator
from aegis.ai.gateway.null import NullGateway
from aegis.ai.slicer import slice_finding
from aegis.analysis.detectors import DEFAULT_REGISTRY
from aegis.cli import main
from aegis.report import console, sarif

EXPECTED = {
    "cmd_injection.c": {"CWE-78", "CWE-120"},
    "loop_taint.c": {"CWE-78", "CWE-134"},
    "memory_bugs.c": {"CWE-401", "CWE-416", "CWE-476"},
    "safe.c": set(),
}


class TestSemanticIndex:
    @pytest.mark.parametrize("name, cwes", EXPECTED.items())
    def test_expected_findings_per_example(self, audit, name, cwes):
        index = audit(name)
        assert set(index.findings_by_cwe()) == cwes

    def test_safe_example_is_clean(self, audit):
        index = audit("safe.c")
        assert index.findings == []
        assert index.errors() == []

    def test_revision_is_deterministic(self, audit):
        assert audit("cmd_injection.c").revision == audit("cmd_injection.c").revision

    def test_stats_are_populated(self, audit):
        stats = audit("cmd_injection.c").stats
        for key in ("functions", "basic_blocks", "instructions", "elapsed_seconds"):
            assert key in stats
        assert stats["ssa_violations"] == 0

    def test_findings_are_ranked_errors_first(self, example_files):
        from aegis.index import build_index

        findings = build_index(example_files).findings
        severities = [f.severity.value for f in findings]
        assert severities == sorted(severities, key=lambda s: {"error": 0, "warning": 1}[s])

    def test_detectors_cover_every_emitted_cwe(self, example_files):
        from aegis.index import build_index

        for finding in build_index(example_files).findings:
            assert DEFAULT_REGISTRY.get(finding.path.cwe) is not None

    def test_ablation_switches_disable_analyses(self, example_files):
        from aegis.index import build_index

        no_taint = build_index(example_files, run_taint=False)
        assert all(f.path.cwe.startswith("CWE-4") for f in no_taint.findings)
        no_memory = build_index(example_files, run_memory=False)
        assert not any(f.path.cwe == "CWE-401" for f in no_memory.findings)


class TestSarif:
    @pytest.fixture
    def log(self, example_files):
        from aegis.index import build_index

        return sarif.to_sarif(build_index(example_files), DEFAULT_REGISTRY, base=Path.cwd())

    def test_schema_and_version(self, log):
        assert log["version"] == "2.1.0"
        assert log["$schema"].endswith("sarif-2.1.0.json")

    def test_every_result_references_a_declared_rule(self, log):
        run = log["runs"][0]
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in declared

    def test_rule_index_points_at_the_right_rule(self, log):
        run = log["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_taint_paths_become_code_flows(self, log):
        results = [r for r in log["runs"][0]["results"] if r["properties"]["cwe"] == "CWE-78"]
        assert results, "expected a command injection result"
        steps = results[0]["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(steps) >= 2
        assert steps[0]["importance"] == "essential"

    def test_uris_are_posix_relative(self, log):
        for result in log["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert "\\" not in uri and not uri.startswith("/")

    def test_levels_are_valid_sarif(self, log):
        for result in log["runs"][0]["results"]:
            assert result["level"] in {"error", "warning", "note", "none"}

    def test_fingerprints_are_stable_across_runs(self, example_files):
        from aegis.index import build_index

        first = {f.path.fingerprint for f in build_index(example_files).findings}
        second = {f.path.fingerprint for f in build_index(example_files).findings}
        assert first == second

    def test_serialises_to_json(self, log):
        assert json.loads(json.dumps(log))["version"] == "2.1.0"


class TestSlicerAndAdjudicator:
    def test_slice_is_smaller_than_the_source(self, audit):
        index = audit("cmd_injection.c")
        excerpt = slice_finding(index.findings[0], index)
        assert excerpt.line_count < excerpt.enclosing_line_count
        assert 0.0 < excerpt.reduction < 1.0

    def test_slice_names_the_cwe_and_the_path(self, audit):
        index = audit("cmd_injection.c")
        text = slice_finding(index.findings[-1], index).text
        assert "CANDIDATE:" in text and "PATH:" in text and "GUARDS ON PATH" in text

    def test_null_gateway_keeps_the_static_verdict(self, audit):
        index = audit("cmd_injection.c")
        before = len(index.findings)
        Adjudicator(NullGateway()).run(index)
        assert len(index.findings) == before
        assert all(f.adjudicator == "null" for f in index.findings)
        assert all(f.exploitable for f in index.findings)

    def test_adjudication_is_deterministic(self, audit):
        index = audit("cmd_injection.c")
        Adjudicator(NullGateway()).run(index)
        first = [f.path.confidence for f in index.findings]
        Adjudicator(NullGateway()).run(index)
        assert [f.path.confidence for f in index.findings] == first

    def test_adjudicator_reports_it_is_disabled(self):
        assert Adjudicator(NullGateway()).enabled is False


class TestConsole:
    def test_renders_without_unicode(self, audit):
        text = console.render(audit("cmd_injection.c"), console.Style(enabled=False, unicode=False))
        assert text.encode("ascii")  # must not raise
        assert "MISSING CONTROL" in text and "SUGGESTED FIX" in text

    def test_clean_file_says_so(self, audit):
        text = console.render(audit("safe.c"), console.Style(enabled=False, unicode=False))
        assert "No security findings" in text

    def test_table_has_a_row_per_finding(self, audit):
        index = audit("memory_bugs.c")
        rows = console.render_table(index, console.Style(enabled=False)).splitlines()
        assert len(rows) == len(index.findings) + 1  # plus header


class TestCli:
    def test_clean_file_exits_zero(self, capsys, example_files):
        code = main(["audit", str(Path(example_files[0]).parent / "safe.c"), "--format", "table"])
        assert code == 0

    def test_findings_exit_nonzero(self, capsys, example_files):
        path = str(Path(example_files[0]).parent / "cmd_injection.c")
        assert main(["audit", path, "--format", "table"]) == 1

    def test_fail_on_threshold_is_respected(self, capsys, example_files):
        path = str(Path(example_files[0]).parent / "memory_bugs.c")
        assert main(["audit", path, "--format", "table", "--fail-on", "warning"]) == 1

    def test_missing_file_is_a_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["audit", "does-not-exist.c"])
        assert exc.value.code == 2

    def test_sarif_to_file(self, tmp_path, example_files):
        out = tmp_path / "out.sarif"
        main(["audit", example_files[0], "--format", "sarif", "-o", str(out)])
        assert json.loads(out.read_text())["version"] == "2.1.0"

    @pytest.mark.parametrize("command", ["ir", "cfg", "dataflow", "summaries", "slice"])
    def test_phase_inspection_commands_run(self, capsys, example_files, command):
        assert main([command, example_files[0]]) == 0
        assert capsys.readouterr().out.strip()

    def test_specs_command_emits_json(self, capsys):
        assert main(["specs"]) == 0
        assert isinstance(json.loads(capsys.readouterr().out), list)
