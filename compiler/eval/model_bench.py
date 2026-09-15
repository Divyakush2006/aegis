"""Model benchmark: which free model is the best adjudicator for Prahari findings?

Model selection happens in two stages, and this file is the second.

1. **Published benchmarks narrow the field.** The free catalogue is filtered to
   models with tool calling and strong independent results on reasoning,
   code comprehension and tool use. ``CANDIDATES`` records that evidence.
2. **This project's own ground truth decides.** No public benchmark measures
   "judge whether this C dataflow path is exploitable", so each shortlisted
   model reviews findings whose truth is already known by the Juliet
   convention: a finding attributed to a ``bad*`` function is real, one
   attributed to a ``good*`` function is a false positive.

Adjudication can do exactly two things, and both are scored:

* **dismiss a false positive** -- precision gained, the reason to use a model;
* **dismiss a real bug** -- recall lost, the thing that must not happen.

**It fits the free tier.** OpenRouter allows 50 free-model requests a day on an
account without purchased credits, so the default run reviews a *stratified
sample*: every known false positive plus one real finding per weakness class,
hard corpus first. Three models times eight findings is 24 requests, and a hard
ceiling refuses any plan that would exceed ``--max-requests``. ``--full``
reviews everything when the quota allows it.

Two recommendations come out, one per use case:

* ``review`` (CLI and CI): highest F1, then fewest real bugs dismissed.
* ``interactive`` (the IDE): among models within 0.05 F1 of the best that
  dismiss no more real bugs than it, the fastest median response.

A ``static`` row -- no model -- is always included. A model below it made the
tool worse, and the report says so.

Usage::

    python eval/model_bench.py                  # the plan; spends nothing
    python eval/model_bench.py --yes            # run the shortlist on the sample
    python eval/model_bench.py --models a:free b:free --yes
    python eval/model_bench.py --mock --yes     # exercise the bench offline
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

from prahari.ai.adjudicator import Adjudicator  # noqa: E402
from prahari.ai.config import is_free_model, load_config  # noqa: E402
from prahari.ai.gateway import build_gateway  # noqa: E402
from prahari.ai.gateway.null import NullGateway  # noqa: E402
from harness import Metrics, _roots, classify_function, expected_cwe, score_file  # noqa: E402

CORPORA = (HERE / "corpus", HERE / "corpus_hard")
OUTPUT = HERE / "model_bench.json"
STATIC = "static"

#: The shortlist, with the published evidence that put each model on it -- and
#: the live reachability probe that kept it there. Excluded after probing with a
#: real forced tool call from this project's key:
#:
#: * Inkling and Inkling Small -- the strongest free models on paper, but their
#:   free endpoints are gated to agent apps listed on OpenRouter (HTTP 403).
#: * Laguna S 2.1, Gemma 4 31B and 26B -- the shared upstream free pool was
#:   congested on every probe (HTTP 429). Unreachable is disqualifying for a
#:   default, however good the benchmark.
#: * Nemotron 3 Super -- reachable, but dominated by Nemotron 3 Ultra: AA index 14
#:   against 23 on the same provider, for under a second of latency saved.
#:
#: Sources: Artificial Analysis Intelligence Index v4.3 model and comparison
#: pages, the Nemotron 3 Ultra technical report, Dots Studio's and Cohere's
#: release notes.
CANDIDATES = {
    "nvidia/nemotron-3-ultra-550b-a55b:free": (
        "strongest reachable free model: AA Intelligence Index 23 (v4.3; Gemma 4 31B 15, "
        "Nemotron 3 Super 14); SWE-bench Verified 65-70%; SWE-bench Multilingual 67.7%; "
        "AA-LCR long context 79%; forced tool call answered in 2.9s"
    ),
    "dots-studio/dots-3-note-preview:free": (
        "SWE-bench Verified 78.4% (vendor-reported, not yet independently verified); "
        "16B active / 280B MoE; 512K context; separate provider (AtlasCloud); "
        "forced tool call answered in 6.5s"
    ),
    "cohere/north-mini-code:free": (
        "SWE-bench Verified 67.6%, SWE-bench Pro 40.2%, Terminal-Bench v2 36.0; "
        "3B active parameters; separate provider (Cohere); forced tool call answered in 4.7s"
    ),
}
SHORTLIST = tuple(CANDIDATES)

DEFAULT_SAMPLE = 8
#: Under the 50/day free cap with room for a live check and a manual test.
DEFAULT_REQUEST_CEILING = 45
INTERACTIVE_F1_TOLERANCE = 0.05


# --- data -------------------------------------------------------------------


@dataclass(frozen=True)
class Item:
    """One finding with known ground truth."""

    path: str
    fingerprint: str
    cwe: str
    label: str  # "TP" or "FP"


@dataclass
class Candidate:
    path: Path
    cwe: str
    findings: int
    items: list[Item]


@dataclass
class ModelResult:
    model: str
    #: Full runs score per function, like the harness; sampled runs per finding.
    full: bool = True
    metrics: Metrics = field(default_factory=Metrics)
    findings: int = 0
    reviewed: int = 0
    tp_kept: int = 0
    tp_dismissed: int = 0
    fp_kept: int = 0
    fp_dismissed: int = 0
    errors: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int | None = None
    prose_answers: int | None = None
    cache_hits: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    seconds: float = 0.0
    failures: list[str] = field(default_factory=list)
    skipped: str = ""
    quota_exhausted: bool = False

    # -- finding-level scores ----------------------------------------------

    @property
    def finding_precision(self) -> float:
        kept = self.tp_kept + self.fp_kept
        return self.tp_kept / kept if kept else 0.0

    @property
    def finding_recall(self) -> float:
        real = self.tp_kept + self.tp_dismissed
        return self.tp_kept / real if real else 0.0

    @property
    def finding_f1(self) -> float:
        p, r = self.finding_precision, self.finding_recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def f1(self) -> float:
        return self.metrics.f1 if self.full else self.finding_f1

    @property
    def median_latency_ms(self) -> float | None:
        return statistics.median(self.latencies_ms) if self.latencies_ms else None

    @property
    def eligible(self) -> bool:
        """Only a complete, error-free run can be recommended."""
        if self.model == STATIC:
            return True
        return not self.skipped and self.errors == 0 and self.reviewed == self.findings

    def rank_key(self):
        latency = self.median_latency_ms if self.median_latency_ms is not None else float("inf")
        return (-round(self.f1, 6), self.tp_dismissed, latency, self.seconds)

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "evidence": CANDIDATES.get(self.model, ""),
            "eligible": self.eligible,
            "skipped": self.skipped,
            "scoring": "per function" if self.full else "per finding (sample)",
            "f1": round(self.f1, 4),
            "metrics": self.metrics.as_dict() if self.full else None,
            "finding_metrics": {
                "precision": round(self.finding_precision, 4),
                "recall": round(self.finding_recall, 4),
                "f1": round(self.finding_f1, 4),
            },
            "findings": self.findings,
            "reviewed": self.reviewed,
            "true_positives_kept": self.tp_kept,
            "true_positives_dismissed": self.tp_dismissed,
            "false_positives_kept": self.fp_kept,
            "false_positives_dismissed": self.fp_dismissed,
            "errors": self.errors,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "tool_calls": self.tool_calls,
            "prose_answers": self.prose_answers,
            "cache_hits": self.cache_hits,
            "median_latency_ms": self.median_latency_ms,
            "seconds": round(self.seconds, 2),
            "quota_exhausted": self.quota_exhausted,
            "failures": self.failures[:5],
        }


# --- the corpus -------------------------------------------------------------


def label_findings(path: Path, cwe: str, index) -> list[Item]:
    """Ground truth for every finding of the expected weakness in one file."""
    attribution = _roots(index)
    items: list[Item] = []
    for finding in index.findings:
        if finding.path.cwe != cwe:
            continue
        kind = classify_function(attribution.get(finding.function, finding.function))
        if kind is None:
            continue
        items.append(
            Item(str(path), finding.path.fingerprint, cwe, "TP" if kind == "bad" else "FP")
        )
    return items


def survey(corpora) -> list[Candidate]:
    """Every scorable file, with its labelled findings."""
    out: list[Candidate] = []
    for corpus in corpora:
        for path in sorted(Path(corpus).glob("*.c")):
            cwe = expected_cwe(path)
            if cwe is None:
                continue
            _cases, index = score_file(path)
            if index is None:
                continue
            out.append(Candidate(path, cwe, len(index.findings), label_findings(path, cwe, index)))
    return out


def select_sample(candidates: list[Candidate], size: int) -> list[Item]:
    """A small, deterministic, informative subset.

    Every known false positive goes in first: they are rare, and dismissing
    them is the only way a model can improve on the compiler. Then real
    findings, one weakness class at a time in rotation, drawn from the hard
    corpus before the generated one -- the hard corpus targets the documented
    limitations, which is where a second opinion has something to say.
    """
    items = [item for candidate in candidates for item in candidate.items]
    if size <= 0 or size >= len(items):
        return items

    chosen = [item for item in items if item.label == "FP"][:size]
    by_cwe: dict[str, list[Item]] = {}
    for item in items:
        if item.label == "TP":
            by_cwe.setdefault(item.cwe, []).append(item)
    for queue in by_cwe.values():
        queue.sort(key=lambda i: ("corpus_hard" not in i.path, i.path, i.fingerprint))
    queues = [by_cwe[cwe] for cwe in sorted(by_cwe)]

    depth = 0
    while len(chosen) < size and any(depth < len(q) for q in queues):
        for queue in queues:
            if depth < len(queue) and len(chosen) < size:
                chosen.append(queue[depth])
        depth += 1
    return chosen


# --- one model --------------------------------------------------------------


class Recorder:
    """A transparent wrapper that records provider latency per request."""

    def __init__(self, gateway) -> None:
        self.gateway = gateway
        #: The live gateway under any cache, so the adjudicator's accounting
        #: and ``enabled`` check see through this wrapper too.
        self.inner = getattr(gateway, "inner", gateway)
        self.latencies: list[float] = []
        self.cached = 0
        self._lock = threading.Lock()

    @property
    def model_id(self) -> str:
        return self.gateway.model_id

    @property
    def available(self) -> bool:
        return self.gateway.available

    @property
    def hits(self) -> int:
        return getattr(self.gateway, "hits", 0)

    def complete(self, system, user, schema=None, temperature=0.0):
        response = self.gateway.complete(system, user, schema=schema, temperature=temperature)
        with self._lock:
            if response.cached:
                self.cached += 1
            else:
                self.latencies.append(response.latency_ms)
        return response


def evaluate(
    model: str,
    candidates: list[Candidate],
    environ: dict,
    use_cache: bool = True,
    workers: int = 1,
    selection: list[Item] | None = None,
    role: str = "review",
) -> ModelResult:
    """Review ``selection`` (or everything, when None) with one model, alone."""
    full = selection is None
    selected = None if full else {(item.path, item.fingerprint) for item in selection}
    result = ModelResult(model=model, full=full)

    recorder: Recorder | None = None
    config = None
    if model != STATIC:
        config = load_config(environ=environ, role=role)
        config.model = model
        config.interactive_model = model
        # Each model is judged on its own answers: a fallback would mix two
        # models' verdicts into one row.
        config.fallback_models = ()
        config.cache_enabled = use_cache
        planned = sum(c.findings for c in candidates) if full else len(selection)
        config.max_requests = max(config.max_requests, planned * (config.max_retries + 1))
        gateway = build_gateway(config)
        if isinstance(gateway, NullGateway):
            result.skipped = gateway.reason or "gateway unavailable"
            return result
        recorder = Recorder(gateway)

    started = time.perf_counter()
    for candidate in candidates:
        if selected is not None and not any(
            (item.path, item.fingerprint) in selected for item in candidate.items
        ):
            continue
        cases, index = score_file(candidate.path)
        if index is None:
            continue
        labels = {i.fingerprint: i.label for i in label_findings(candidate.path, candidate.cwe, index)}
        attribution = _roots(index)
        if selected is not None:
            index.findings = [
                f for f in index.findings
                if (str(candidate.path), f.path.fingerprint) in selected
            ]
        result.findings += len(index.findings)

        if recorder is not None and index.findings:
            adjudicator = Adjudicator(recorder, max_workers=workers, redact_paths=config.redact_paths)
            adjudicator.run(index)
            result.reviewed += adjudicator.stats.adjudicated
            result.errors += adjudicator.stats.errors
            for failure in adjudicator.stats.failures:
                if failure not in result.failures:
                    result.failures.append(failure)
            if getattr(recorder.inner, "quota_exhausted", None) is not None:
                result.quota_exhausted = True

        surviving: set[str] = set()
        for finding in index.findings:
            label = labels.get(finding.path.fingerprint)
            if label is None:
                continue
            dismissed = finding.exploitable is False
            if label == "TP":
                result.tp_dismissed += dismissed
                result.tp_kept += not dismissed
            else:
                result.fp_dismissed += dismissed
                result.fp_kept += not dismissed
            if not dismissed:
                surviving.add(attribution.get(finding.function, finding.function))

        if full:
            for case in cases:
                detected = case.function in surviving
                if case.kind == "bad":
                    result.metrics.add("TP" if detected else "FN")
                else:
                    result.metrics.add("FP" if detected else "TN")

        if result.quota_exhausted:
            break

    result.seconds = time.perf_counter() - started
    if recorder is None:
        result.reviewed = result.findings
        return result

    inner = recorder.inner
    result.input_tokens = getattr(inner, "input_tokens", 0)
    result.output_tokens = getattr(inner, "output_tokens", 0)
    result.cache_hits = recorder.hits
    result.latencies_ms = list(recorder.latencies)
    if hasattr(inner, "tool_call_responses"):
        result.tool_calls = inner.tool_call_responses
        result.prose_answers = inner.prose_responses
    return result


# --- planning ---------------------------------------------------------------


def catalogue_for(environ: dict):
    """The live catalogue, or None when the provider has none or it is unreachable."""
    config = load_config(environ=environ)
    if not config.configured or config.provider != "openrouter":
        return None
    try:
        from prahari.ai.catalogue import fetch_models

        return {m.id: m for m in fetch_models(config.base_url, config.api_key, config.provider)}
    except Exception as exc:
        print(f"  (catalogue unavailable: {exc}; model ids will not be verified)")
        return None


def suggestions(model: str, catalogue: dict) -> list[str]:
    vendor = model.split("/", 1)[0] + "/"
    related = [m for m in catalogue.values() if m.id.startswith(vendor) and is_free_model(m.id)]
    related.sort(key=lambda m: (not m.supports_tools, -m.context_length))
    return [m.id for m in related[:6]]


def plan(models, catalogue) -> tuple[list[str], list[str]]:
    """Verify each id is free and reachable before anything is spent."""
    runnable: list[str] = []
    lines = [f"  {'MODEL':<44} {'STATUS':<22} TOOLS"]
    for model in models:
        if not is_free_model(model):
            lines.append(f"  {model:<44} {'REFUSED: not a :free id':<22}")
            continue
        if catalogue is None:
            runnable.append(model)
            lines.append(f"  {model:<44} {'unverified':<22} ?")
            continue
        info = catalogue.get(model)
        if info is None:
            lines.append(f"  {model:<44} {'NOT IN CATALOGUE':<22}")
            hint = suggestions(model, catalogue)
            if hint:
                lines.append(f"      free from {model.split('/')[0]}: {', '.join(hint)}")
            continue
        runnable.append(model)
        lines.append(f"  {model:<44} {'ok (free)':<22} {'yes' if info.supports_tools else 'no'}")
    return runnable, lines


# --- reporting --------------------------------------------------------------


def render(results: list[ModelResult]) -> str:
    header = (
        "| Model | F1 | Precision | Recall | Real bugs dismissed | False positives dismissed "
        "| Errors | Tool calls | Median latency | Tokens in/out |"
    )
    lines = [header, "|---|---:|---:|---:|---:|---:|---:|---|---:|---:|"]
    for r in results:
        if r.skipped:
            lines.append(f"| {r.model} | — | — | — | — | — | — | — | — | skipped: {r.skipped} |")
            continue
        precision = r.metrics.precision if r.full else r.finding_precision
        recall = r.metrics.recall if r.full else r.finding_recall
        tools = "—" if r.tool_calls is None else f"{r.tool_calls}/{r.tool_calls + r.prose_answers}"
        latency = "—" if r.median_latency_ms is None else f"{r.median_latency_ms / 1000:.1f}s"
        tokens = "—" if r.model == STATIC else f"{r.input_tokens:,}/{r.output_tokens:,}"
        lines.append(
            f"| {r.model} | {r.f1:.3f} | {precision:.1%} | {recall:.1%} | {r.tp_dismissed} | "
            f"{r.fp_dismissed} | {r.errors} | {tools} | {latency} | {tokens} |"
        )
    return "\n".join(lines)


def recommend(results: list[ModelResult]) -> ModelResult | None:
    """The review use case: accuracy first."""
    models = [r for r in results if r.model != STATIC and r.eligible]
    return sorted(models, key=ModelResult.rank_key)[0] if models else None


def recommend_interactive(results: list[ModelResult]) -> ModelResult | None:
    """The interactive use case: the fastest model that is nearly as right."""
    models = [r for r in results if r.model != STATIC and r.eligible]
    if not models:
        return None
    best = max(r.f1 for r in models)
    fewest = min(r.tp_dismissed for r in models)
    close = [r for r in models if r.f1 >= best - INTERACTIVE_F1_TOLERANCE and r.tp_dismissed == fewest]
    return min(
        close,
        key=lambda r: (r.median_latency_ms if r.median_latency_ms is not None else float("inf"), -r.f1),
    )


# --- entry point ------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rank free models as adjudicators for Prahari.")
    parser.add_argument("--models", nargs="+", help="model ids to compare (default: the shortlist)")
    parser.add_argument("--yes", action="store_true", help="spend requests; without it, only plan")
    parser.add_argument("--sample", type=int, help=f"findings to review per model (default {DEFAULT_SAMPLE})")
    parser.add_argument("--full", action="store_true", help="review every finding (needs quota)")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_REQUEST_CEILING,
                        help="refuse a plan needing more requests than this")
    parser.add_argument("--role", choices=["review", "interactive"], default="review",
                        help="reasoning effort to run the models at")
    parser.add_argument("--no-cache", action="store_true", help="bypass the verdict cache")
    parser.add_argument("--workers", type=int, default=1,
                        help="concurrent requests (1 keeps latency comparable)")
    parser.add_argument("--mock", action="store_true", help="run against eval/mock_model.py")
    parser.add_argument("--output", default=str(OUTPUT), help="where to write the JSON report")
    args = parser.parse_args(argv)

    environ = dict(os.environ)
    server = None
    if args.mock:
        from mock_model import serve

        server = serve(port=0)
        environ.update(
            {
                "OPENROUTER_API_KEY": "sk-or-v1-mock",
                "PRAHARI_API_BASE": f"http://127.0.0.1:{server.server_address[1]}",
                "PRAHARI_AI_PROVIDER": "openrouter",
                "PRAHARI_AI_RPM": "0",
            }
        )
        args.no_cache = True

    try:
        default_models = ["mock/model-a:free", "mock/model-b:free"] if args.mock else list(SHORTLIST)
        models = list(args.models or default_models)
        config = load_config(environ=environ)
        print(f"provider: {config.provider}   key: {config.key_fingerprint}   "
              f"endpoint: {config.base_url}   free-only: {config.free_only}")
        if not config.configured:
            print("\nno API key found -- add OPENROUTER_API_KEY to the project .env first.")
            return 2

        print("surveying the corpora...")
        candidates = survey(CORPORA)
        if args.full:
            size = 0
        elif args.sample is not None:
            size = args.sample
        else:
            size = 0 if args.mock else DEFAULT_SAMPLE
        selection = None if size == 0 else select_sample(candidates, size)
        per_model = sum(c.findings for c in candidates) if selection is None else len(selection)

        if selection is None:
            print(f"scope: every finding ({per_model}), scored per function")
        else:
            real = sum(1 for i in selection if i.label == "TP")
            print(f"scope: stratified sample of {len(selection)} findings "
                  f"({real} real, {len(selection) - real} known false positives; "
                  f"classes: {', '.join(sorted({i.cwe for i in selection}))}), scored per finding")

        catalogue = None if args.mock else catalogue_for(environ)
        runnable, lines = plan(models, catalogue)
        print("\n".join(lines))
        total = per_model * len(runnable)
        print(f"\nrequests: {per_model} per model x {len(runnable)} models = {total}"
              f"{'' if args.mock else f'  (ceiling {args.max_requests}; free tier allows 50/day)'}")

        if not runnable:
            print("\nnothing to run: no requested model is free and available to this key.")
            return 2
        if not args.mock and total > args.max_requests:
            print(f"\nrefusing: the plan needs {total} requests. Use --sample, fewer --models, "
                  "or raise --max-requests if your quota allows it.")
            return 2
        if not args.yes:
            print("\nplan only -- nothing was spent. Re-run with --yes to execute.")
            return 0

        results = [evaluate(STATIC, candidates, environ, True, args.workers, selection, args.role)]
        stopped = False
        for model in runnable:
            if stopped:
                results.append(ModelResult(model=model, full=selection is None,
                                           skipped="quota exhausted earlier in this run"))
                continue
            print(f"\nreviewing with {model} ...", flush=True)
            result = evaluate(model, candidates, environ, not args.no_cache, args.workers,
                              selection, args.role)
            results.append(result)
            if result.skipped:
                print(f"  skipped: {result.skipped}")
                continue
            status = "ok" if result.eligible else f"INCOMPLETE ({result.errors} errors)"
            latency = result.median_latency_ms
            print(f"  {status}: F1 {result.f1:.3f}, {result.tp_dismissed} real bugs dismissed, "
                  f"{result.fp_dismissed} false positives dismissed, "
                  f"median {latency / 1000:.1f}s" if latency is not None else
                  f"  {status}: F1 {result.f1:.3f} (all answers cached)")
            for failure in result.failures[:2]:
                print(f"    {failure}")
            if result.quota_exhausted:
                print("  the daily quota is exhausted; remaining models are skipped")
                stopped = True

        print()
        print(render(results))

        baseline = results[0]
        review = recommend(results)
        interactive = recommend_interactive(results)
        print()
        if review is None:
            print("no model completed cleanly; the static verdicts remain the recommendation.")
        else:
            delta = review.f1 - baseline.f1
            verdict = "improves on" if delta > 0 else ("matches" if delta == 0 else "is WORSE than")
            print(f"review:      {review.model} -- F1 {review.f1:.3f}, {verdict} "
                  f"static analysis alone ({baseline.f1:.3f})")
            if interactive is not None:
                latency = interactive.median_latency_ms
                print(f"interactive: {interactive.model} -- F1 {interactive.f1:.3f}, "
                      f"median {latency / 1000:.1f}s" if latency is not None else
                      f"interactive: {interactive.model}")
            if delta < 0:
                print("  every model reduced accuracy; leave adjudication off.")
            else:
                print("\n  to use them, set in .env:")
                print(f"    PRAHARI_MODEL={review.model}")
                if interactive is not None:
                    print(f"    PRAHARI_MODEL_INTERACTIVE={interactive.model}")

        report = {
            "provider": config.provider,
            "role": args.role,
            "corpora": [Path(c).name for c in CORPORA],
            "sample": None if selection is None else {
                "size": len(selection),
                "true_positives": sum(1 for i in selection if i.label == "TP"),
                "false_positives": sum(1 for i in selection if i.label == "FP"),
                "items": [{"file": Path(i.path).name, "cwe": i.cwe, "label": i.label} for i in selection],
            },
            "recommended": review.model if review else None,
            "recommended_interactive": interactive.model if interactive else None,
            "results": [r.as_dict() for r in results],
        }
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.output}")
        return 0
    finally:
        if server is not None:
            server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
