"""Evaluation harness and ablation matrix.

These assert the *shape* of the results, not just that the harness runs. A
detection rate that silently drops, or a false positive appearing where the
corpus expects none, fails the build -- which is the only way published numbers
stay true as the analysis changes.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from ablation import CONFIGURATIONS, run_matrix  # noqa: E402
from check_determinism import check_each, differences, strip  # noqa: E402
from check_invariants import check  # noqa: E402
from harness import Metrics, classify_function, expected_cwe, run, variant_of  # noqa: E402

CORPUS = ROOT / "eval" / "corpus"
HARD = ROOT / "eval" / "corpus_hard"


class TestGroundTruth:
    @pytest.mark.parametrize(
        "name, cwe",
        [
            ("CWE78_os_command_injection__01.c", "CWE-78"),
            ("CWE120_buffer_overflow_strcpy__05.c", "CWE-120"),
            ("CWE476_null_pointer_dereference__03.c", "CWE-476"),
        ],
    )
    def test_cwe_parsed_from_filename(self, name, cwe):
        assert expected_cwe(Path(name)) == cwe

    def test_juliet_variant_suffix(self):
        assert variant_of(Path("CWE78_x__04.c")) == "04"

    @pytest.mark.parametrize(
        "name, kind",
        [
            ("bad", "bad"),
            ("badSink", "bad"),
            ("goodG2B", "good"),
            ("goodB2G1", "good"),
            ("helper", None),
            ("main", None),
        ],
    )
    def test_function_classification(self, name, kind):
        assert classify_function(name) == kind


class TestMetrics:
    def test_rates(self):
        m = Metrics(tp=8, fp=2, fn=2, tn=8)
        assert m.detection_rate == 0.8
        assert m.false_positive_rate == 0.2
        assert m.precision == 0.8
        assert m.f1 == pytest.approx(0.8)

    def test_empty_is_zero_not_an_error(self):
        assert Metrics().detection_rate == 0.0 and Metrics().f1 == 0.0


class TestMainCorpus:
    @pytest.fixture(scope="class")
    def result(self):
        return run(CORPUS)

    def test_corpus_is_present_and_paired(self, result):
        assert result.files_scored >= 30
        kinds = {c.kind for c in result.cases}
        assert kinds == {"bad", "good"}

    def test_no_parse_failures(self, result):
        assert result.parse_failures == []

    def test_nothing_is_excluded(self, result):
        assert result.exclusions == {}

    def test_every_flaw_is_detected(self, result):
        assert result.metrics.fn == 0, [c.file for c in result.failures() if c.outcome == "FN"]

    def test_no_false_positives(self, result):
        assert result.metrics.fp == 0, [c.file for c in result.failures() if c.outcome == "FP"]

    def test_all_seven_weakness_classes_exercised(self, result):
        assert set(result.by_cwe()) == {
            "CWE-78",
            "CWE-120",
            "CWE-134",
            "CWE-401",
            "CWE-415",
            "CWE-416",
            "CWE-476",
        }

    def test_detection_holds_across_every_flow_variant(self, result):
        for variant, metrics in result.by_variant().items():
            assert metrics.detection_rate == 1.0, f"variant {variant} regressed"


class TestHardCorpus:
    """The hard cases target documented limitations; the numbers are expected
    to be worse, and are pinned so they cannot quietly get worse still."""

    @pytest.fixture(scope="class")
    def result(self):
        return run(HARD)

    def test_detection_does_not_regress(self, result):
        assert result.metrics.detection_rate == 1.0

    def test_false_positives_are_bounded_and_known(self, result):
        assert result.metrics.fp <= 1
        for case in result.failures():
            # The only accepted false positive is the bounds-checked copy,
            # which requires evaluating sizeof -- a stated limitation.
            assert "bounds_checked" in case.file, case.file

    def test_global_laundering_is_caught(self, result):
        cases = {c.file: c for c in result.cases if c.kind == "bad"}
        assert cases["CWE78_taint_through_global__h01.c"].detected

    def test_struct_field_flow_is_caught(self, result):
        cases = {c.file: c for c in result.cases if c.kind == "bad"}
        assert cases["CWE78_taint_through_struct__h02.c"].detected


class TestAblation:
    @pytest.fixture(scope="class")
    def matrix(self):
        return run_matrix(CORPUS)

    def test_every_configuration_runs(self, matrix):
        assert len(matrix) == len(CONFIGURATIONS)
        assert all(r.files_scored > 0 for _c, r in matrix)

    def test_pattern_baseline_has_a_high_false_positive_rate(self, matrix):
        """The headline comparison: name matching alone is imprecise."""
        _config, baseline = matrix[0]
        assert baseline.metrics.false_positive_rate > 0.5

    def test_dataflow_eliminates_those_false_positives(self, matrix):
        _config, baseline = matrix[0]
        _config, full = matrix[3]
        assert full.metrics.false_positive_rate < baseline.metrics.false_positive_rate
        assert full.metrics.precision > baseline.metrics.precision

    def test_interprocedural_summaries_increase_recall(self, matrix):
        _config, intra = matrix[1]
        _config, inter = matrix[2]
        assert inter.metrics.tp > intra.metrics.tp

    def test_full_static_configuration_is_exact_on_this_corpus(self, matrix):
        _config, full = matrix[3]
        assert full.metrics.fp == 0 and full.metrics.fn == 0

    def test_null_adjudication_reproduces_the_static_result(self, matrix):
        """The control row must change nothing, or it is not a control."""
        _config, full = matrix[3]
        _config, adjudicated = matrix[4]
        assert adjudicated.metrics.as_dict() == full.metrics.as_dict()


class TestInvariantChecker:
    """The report-level gate CI runs after an adjudicated audit.

    The unit tests in ``test_ai.py`` check the invariants on objects; this
    checks the checker, because a gate that cannot fail is not a gate.
    """

    def finding(self, fingerprint="a", severity="error", confidence=None):
        return {
            "fingerprint": fingerprint,
            "severity": severity,
            "confidence": confidence,
            "ruleId": "aegis/cwe78",
        }

    def reports(self, base_findings, live_findings, stats=None):
        return (
            {"findings": base_findings},
            {
                "findings": live_findings,
                "adjudication": stats or {"model": "m", "candidates": 1, "adjudicated": 1},
            },
        )

    def test_a_clean_demotion_passes(self):
        base, live = self.reports(
            [self.finding(confidence=None)], [self.finding(confidence=0.4)]
        )
        assert check(base, live) == []

    def test_an_invented_finding_fails(self):
        base, live = self.reports(
            [self.finding("a")],
            [self.finding("a"), self.finding("b")],
            {"model": "m", "candidates": 2, "adjudicated": 2},
        )
        assert any("invented" in failure for failure in check(base, live))

    def test_a_dropped_finding_fails(self):
        base, live = self.reports([self.finding("a"), self.finding("b")], [self.finding("a")])
        assert any("lost" in failure for failure in check(base, live))

    def test_a_raised_confidence_fails(self):
        base, live = self.reports(
            [self.finding(confidence=0.3)], [self.finding(confidence=0.9)]
        )
        assert any("confidence rose" in failure for failure in check(base, live))

    def test_an_unstated_confidence_counts_as_full(self):
        """None means the analysis made no claim, which reports as 1.0.

        Reading it as 0.0 would make every demotion look like a promotion.
        """
        base, live = self.reports(
            [self.finding(confidence=None)], [self.finding(confidence=0.9)]
        )
        assert check(base, live) == []
        base, live = self.reports(
            [self.finding(confidence=0.9)], [self.finding(confidence=None)]
        )
        assert any("confidence rose" in failure for failure in check(base, live))

    def test_a_changed_severity_fails(self):
        base, live = self.reports(
            [self.finding(severity="warning")], [self.finding(severity="error")]
        )
        assert any("severity changed" in failure for failure in check(base, live))

    def test_an_adjudicated_baseline_is_refused(self):
        base, live = self.reports([self.finding()], [self.finding()])
        base["adjudication"] = {"model": "null"}
        assert any("baseline is itself" in failure for failure in check(base, live))

    def test_adjudication_errors_fail_the_gate(self):
        base, live = self.reports(
            [self.finding()],
            [self.finding()],
            {"model": "m", "candidates": 1, "adjudicated": 1, "errors": 1},
        )
        assert any("errors" in failure for failure in check(base, live))

    def test_partial_coverage_fails(self):
        base, live = self.reports(
            [self.finding()],
            [self.finding()],
            {"model": "m", "candidates": 4, "adjudicated": 2},
        )
        assert any("only 2 of 4" in failure for failure in check(base, live))


class TestDeterminismChecker:
    """The gate that keeps the reproducibility claim true."""

    def test_the_real_pipeline_is_reproducible(self):
        assert check_each(str(HARD)) == 0

    def test_volatile_timings_are_ignored(self):
        a = {"stats": {"elapsed_seconds": 0.04, "findings": 3}}
        b = {"stats": {"elapsed_seconds": 0.09, "findings": 3}}
        assert differences(strip(a), strip(b)) == []

    def test_a_changed_finding_is_caught(self):
        a = {"findings": [{"line": 19}]}
        b = {"findings": [{"line": 20}]}
        assert differences(strip(a), strip(b)) == ["findings[0].line: 19 -> 20"]

    def test_a_changed_ordering_is_caught(self):
        """Ordering is part of the output: findings are ranked, not a set."""
        a = {"findings": [{"id": "x"}, {"id": "y"}]}
        b = {"findings": [{"id": "y"}, {"id": "x"}]}
        assert differences(strip(a), strip(b))

    def test_an_extra_finding_is_caught(self):
        a = {"findings": [{"id": "x"}]}
        b = {"findings": [{"id": "x"}, {"id": "y"}]}
        assert any("length changed" in d for d in differences(strip(a), strip(b)))

    def test_a_new_field_is_caught(self):
        assert differences({"a": 1}, {"a": 1, "b": 2}) == ["b: appeared"]


class TestModelBench:
    """The benchmark that picks a model must itself be trustworthy.

    Its ranking is only meaningful if the static row reproduces the harness
    exactly and the scoring punishes a model for dismissing real bugs.
    """

    def test_static_row_reproduces_the_harness(self):
        import model_bench

        candidates = model_bench.survey(model_bench.CORPORA)
        static = model_bench.evaluate(model_bench.STATIC, candidates, {}, True, 1, None)
        expected = Metrics()
        for corpus in model_bench.CORPORA:
            for field_name in ("tp", "fp", "fn", "tn"):
                setattr(
                    expected,
                    field_name,
                    getattr(expected, field_name) + getattr(run(corpus).metrics, field_name),
                )
        assert static.metrics.as_dict() == expected.as_dict()

    def test_a_mock_run_ranks_against_ground_truth(self, tmp_path):
        import json

        import model_bench

        output = tmp_path / "bench.json"
        assert model_bench.main(["--mock", "--yes", "--models", "mock/a:free", "--output", str(output)]) == 0
        report = json.loads(output.read_text(encoding="utf-8"))
        static, reviewed = report["results"]
        assert static["model"] == "static"
        assert reviewed["eligible"] is True
        assert reviewed["errors"] == 0
        assert reviewed["reviewed"] == reviewed["findings"]
        assert reviewed["true_positives_dismissed"] == 0
        assert reviewed["metrics"]["f1"] >= static["metrics"]["f1"]
        assert report["recommended"] == "mock/a:free"

    def test_planning_spends_nothing_and_writes_nothing(self, tmp_path):
        import model_bench

        output = tmp_path / "bench.json"
        assert model_bench.main(["--mock", "--models", "mock/a:free", "--output", str(output)]) == 0
        assert not output.exists()

    def test_dismissing_real_bugs_ranks_below_a_cautious_model(self):
        from model_bench import ModelResult, recommend

        careless = ModelResult(model="careless", findings=10, reviewed=10)
        careless.metrics = Metrics(tp=8, fp=0, fn=2, tn=10)   # dismissed two real bugs
        careless.tp_dismissed = 2
        careless.cost_usd = 0.0001

        cautious = ModelResult(model="cautious", findings=10, reviewed=10)
        cautious.metrics = Metrics(tp=10, fp=1, fn=0, tn=9)
        cautious.cost_usd = 0.05

        assert recommend([ModelResult(model="static"), careless, cautious]).model == "cautious"

    def test_an_incomplete_run_is_never_recommended(self):
        from model_bench import ModelResult, recommend

        flaky = ModelResult(model="flaky", findings=10, reviewed=7, errors=3)
        flaky.metrics = Metrics(tp=10, fp=0, fn=0, tn=10)
        assert flaky.eligible is False
        assert recommend([ModelResult(model="static"), flaky]) is None
