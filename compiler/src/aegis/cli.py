"""Command line interface.

Subcommands map one-to-one onto compiler phases, so each stage is inspectable on
its own -- ``aegis ir`` dumps three-address code, ``aegis cfg`` dumps the graph,
``aegis dataflow`` dumps the classical analyses, ``aegis audit`` runs everything.
Being able to show a single phase is what makes the pipeline demonstrable and
debuggable rather than a black box that emits findings.

Exit codes follow the convention CI systems expect:
``0`` clean, ``1`` findings at or above the threshold, ``2`` usage or input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import live_vars, reaching_defs
from .analysis.detectors import DEFAULT_REGISTRY
from .analysis.specs import SpecTable
from .index import build_index
from .report import console, sarif

VERSION = "0.1.0"
_SEVERITY_ORDER = {"error": 0, "warning": 1, "note": 2}


def _expand(paths: list[str]) -> list[str]:
    """Accept files and directories; directories are searched for C sources."""
    out: list[str] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            out.extend(sorted(str(p) for p in path.rglob("*.c")))
        elif path.exists():
            out.append(str(path))
        else:
            print(f"aegis: no such file or directory: {raw}", file=sys.stderr)
    return out


def _load(args) -> object:
    files = _expand(args.paths)
    if not files:
        print("aegis: no input files", file=sys.stderr)
        raise SystemExit(2)
    return build_index(
        files,
        specs=SpecTable(),
        registry=DEFAULT_REGISTRY,
        use_cpp=getattr(args, "cpp", False),
        run_taint=not getattr(args, "no_taint", False),
        run_memory=not getattr(args, "no_memory", False),
    )


# --- subcommands ------------------------------------------------------------


def cmd_audit(args) -> int:
    index = _load(args)

    if getattr(args, "adjudicate", False):
        _adjudicate(index, args)

    threshold = _SEVERITY_ORDER[args.fail_on]
    triggering = [
        f for f in index.findings if _SEVERITY_ORDER[f.severity.value] <= threshold
    ]

    if args.format == "sarif":
        output = sarif.dumps(index, DEFAULT_REGISTRY, base=Path.cwd())
    elif args.format == "json":
        output = json.dumps(
            {
                "revision": index.revision,
                "stats": index.stats,
                "findings": [
                    {
                        "ruleId": f.rule_id,
                        "cwe": f.path.cwe,
                        "severity": f.severity.value,
                        "message": f.message,
                        "file": f.path.sink.file,
                        "line": f.path.sink.line,
                        "fingerprint": f.path.fingerprint,
                        "adjudicator": f.adjudicator,
                        "exploitable": f.exploitable,
                        "confidence": f.path.confidence,
                        "reason": f.reason,
                        "steps": [
                            {
                                "kind": s.kind,
                                "file": s.location.file,
                                "line": s.location.line,
                                "value": s.value,
                                "snippet": s.snippet,
                                "explanation": s.explanation,
                            }
                            for s in f.path.steps
                        ],
                    }
                    for f in index.findings
                ],
                "exclusions": [e.as_dict() for e in index.exclusions],
                **({"adjudication": index.stats["adjudication"]}
                   if "adjudication" in index.stats else {}),
            },
            indent=2,
        )
    elif args.format == "table":
        output = console.render_table(index)
    else:
        output = console.render(index)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"wrote {args.format} report to {args.output}  ({len(index.findings)} findings)")
    else:
        print(output)

    return 1 if triggering else 0


def _adjudicate(index, args) -> None:
    """Run the adjudication pass and fold its statistics into the index.

    Never raises. Adjudication is a second opinion on findings the compiler has
    already produced, so a missing key, a rate limit or an unreachable endpoint
    degrades the run to the static verdict rather than failing it.
    """
    from .ai.adjudicator import Adjudicator
    from .ai.config import load_config
    from .ai.gateway import build_gateway

    # The CLI is the accuracy-first use case: batch review, nobody waiting.
    config = load_config(role="review")
    if getattr(args, "model", None):
        config.model = args.model
    if getattr(args, "no_ai_cache", False):
        config.cache_enabled = False

    gateway = build_gateway(config)
    adjudicator = Adjudicator(
        gateway,
        max_workers=getattr(args, "ai_workers", 4),
        redact_paths=config.redact_paths,
    )
    adjudicator.run(index)
    index.stats["adjudication"] = adjudicator.stats.as_dict()

    stats = adjudicator.stats
    if not adjudicator.enabled:
        reason = getattr(gateway, "reason", "") or "no API key configured"
        hint = " (add OPENROUTER_API_KEY to .env to enable adjudication)" if "API key" in reason else ""
        print(
            f"aegis: no model configured -- {reason}; static verdicts retained{hint}",
            file=sys.stderr,
        )
        return
    print(
        f"aegis: adjudicated {stats.adjudicated}/{stats.candidates} findings "
        f"via {stats.model} -- {stats.dismissed} dismissed, {stats.demoted} demoted, "
        f"{stats.cache_hits} cached, {stats.errors} errors "
        f"({stats.input_tokens}+{stats.output_tokens} tokens, "
        f"{stats.elapsed_seconds:.1f}s)",
        file=sys.stderr,
    )
    for failure in stats.failures[:3]:
        print(f"aegis:   {failure}", file=sys.stderr)
    _report_routing(gateway)


def _report_routing(gateway) -> None:
    """Say which model answered and how much rate limit remains.

    With fallbacks a verdict can come from a model other than the one
    configured; a report that hid that would misattribute every opinion.
    """
    inner = getattr(gateway, "inner", gateway)
    routed = getattr(inner, "routed_models", {}) or {}
    if len(routed) > 1 or (routed and next(iter(routed)) != getattr(inner, "model_id", "")):
        answered = ", ".join(f"{model} x{count}" for model, count in sorted(routed.items()))
        print(f"aegis:   answered by: {answered}", file=sys.stderr)
    limit = getattr(inner, "rate_limit", {}) or {}
    if limit.get("remaining") is not None:
        print(
            f"aegis:   rate limit: {limit['remaining']} of {limit.get('limit', '?')} remaining",
            file=sys.stderr,
        )


def _list_models(config) -> int:
    """Ask the provider what this key can reach, ranked for this task.

    The roster changes constantly, so a list baked into the source would be
    wrong within a month. Asking is the only answer that stays true.
    """
    from .ai.catalogue import fetch_models, rank_for_adjudication

    try:
        models = fetch_models(config.base_url, config.api_key, config.provider)
    except ValueError:
        print(
            f"aegis: {config.provider} does not publish a model catalogue; "
            "set AEGIS_MODEL directly",
            file=sys.stderr,
        )
        return 2
    except RuntimeError as exc:
        print(f"aegis: {exc}", file=sys.stderr)
        return 1

    ranked = rank_for_adjudication(models, limit=25, free_only=config.free_only)
    scope = "free models" if config.free_only else "candidates"
    print(f"\n{len(models)} models reachable; {len(ranked)} {scope} ranked for adjudication\n")
    print(f"  {'MODEL':<52} {'TOOLS':<6} {'PRICE':>9}  CONTEXT")
    for info in ranked:
        price = "free" if info.id.endswith(":free") else f"{info.price_per_million:.2f}/M"
        print(
            f"  {info.id:<52} {'yes' if info.supports_tools else 'no':<6} "
            f"{price:>9}  {info.context_length:,}"
        )
    print(
        "\nRanked by tool support, then price -- candidates to try, not a quality"
        "\njudgement. Which one actually judges C dataflow paths well is measured by:"
        "\n  python eval/model_bench.py --models <id> <id> ..."
    )
    return 0


def cmd_ai(args) -> int:
    """Report how adjudication is configured, and optionally prove it works."""
    from .ai.adjudicator import SYSTEM_PROMPT, VERDICT_SCHEMA
    from .ai.config import load_config
    from .ai.gateway import build_gateway
    from .ai.gateway.null import NullGateway

    role = getattr(args, "role", None) or "review"
    config = load_config(role=role)
    if getattr(args, "model", None):
        config.model = args.model
    description = config.describe()

    if args.json:
        print(json.dumps(description, indent=2))
    else:
        print("adjudication configuration")
        for key, value in description.items():
            if key == "sources":
                continue
            print(f"  {key:<18} {value}")
        if description["sources"]:
            print("  resolved from")
            for key, origin in sorted(description["sources"].items()):
                print(f"    {key:<16} {origin}")

    if not config.configured:
        print(
            "\nno API key found. Add OPENROUTER_API_KEY=sk-or-... to a .env file at the "
            "project root\n(or export AEGIS_API_KEY / ANTHROPIC_API_KEY). The compiler and "
            "every analysis\nrun unchanged without it.",
            file=sys.stderr,
        )
        return 0 if not args.check else 1

    if getattr(args, "models", False):
        return _list_models(config)

    if not args.check:
        return 0

    # --check spends exactly one request, on a fixed synthetic candidate, so a
    # user can confirm credentials and model access before running an audit
    # over a real codebase.
    gateway = build_gateway(config, use_cache=False)
    if isinstance(gateway, NullGateway):
        reason = getattr(gateway, "reason", "") or "unknown reason"
        print(f"\ngateway unavailable ({reason}); falling back to the deterministic path",
              file=sys.stderr)
        return 1
    probe = (
        "CANDIDATE: CWE-78 (OS Command Injection)\n\nPATH:\n"
        '  [SOURCE   ] probe.c:1     char *p = getenv("X");\n'
        "  [SINK     ] probe.c:2     system(p);\n\nGUARDS ON PATH: none"
    )
    try:
        response = gateway.complete(
            system=SYSTEM_PROMPT, user=probe, schema=VERDICT_SCHEMA, temperature=0.0
        )
    except Exception as exc:
        print(f"\nlive check FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        f"\nlive check OK -- {response.model} answered in {response.latency_ms:.0f} ms "
        f"({response.usage.get('input_tokens', 0)}+{response.usage.get('output_tokens', 0)} tokens)"
    )
    print(f"  role: {config.role}   verdict: exploitable={response.data.get('exploitable')} "
          f"confidence={response.data.get('confidence')}")
    _report_routing(gateway)
    return 0


def cmd_ir(args) -> int:
    index = _load(args)
    print(index.module.dump())
    return 0


def cmd_cfg(args) -> int:
    index = _load(args)
    for name, cfg in index.cfgs.items():
        if args.function and name != args.function:
            continue
        print(cfg.to_dot() if args.dot else cfg.dump())
        print()
    return 0


def cmd_dataflow(args) -> int:
    index = _load(args)
    for name, cfg in index.cfgs.items():
        if args.function and name != args.function:
            continue
        rd = reaching_defs.run(cfg)
        lv = live_vars.run(cfg)
        print(f"function {name}")
        print(f"  reaching definitions converged after {rd.iterations} block visits")
        print(f"  live variables       converged after {lv.iterations} block visits")
        for label in cfg.order:
            if label not in cfg.blocks:
                continue
            entering = sorted(str(d) for d in rd.at_block_entry(label))
            live = sorted(lv.at_block_entry(label))
            print(f"  {label}")
            print(f"      reaching-in : {', '.join(entering) or '-'}")
            print(f"      live-in     : {', '.join(live) or '-'}")
        dead = live_vars.dead_stores(cfg)
        if dead:
            print("  dead stores:")
            for instr in dead:
                print(f"      line {instr.loc.line}: {instr}")
        print()
    return 0


def cmd_build(args) -> int:
    """Generate code: LLVM IR, native assembly, an object file, or JIT-run it."""
    from .codegen import llvm_emitter

    index = _load(args)
    if index.errors() and not args.force:
        for diagnostic in index.errors()[:10]:
            print(f"  {diagnostic}", file=sys.stderr)
        print("aegis: refusing to generate code for a program with errors "
              "(use --force to try anyway)", file=sys.stderr)
        return 2

    try:
        if args.run is not None:
            value = llvm_emitter.jit_call(index.module, args.run)
            print(f"{args.run}() returned {value}")
            return 0
        if args.emit == "asm":
            output = llvm_emitter.emit_assembly(index.module)
        elif args.emit == "obj":
            data = llvm_emitter.emit_object(index.module, optimise=args.opt)
            target = args.output or "a.o"
            Path(target).write_bytes(data)
            print(f"wrote {len(data)} bytes to {target}")
            return 0
        else:
            output = llvm_emitter.emit_ir(index.module)
    except Exception as exc:
        print(f"aegis: code generation failed: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"wrote {args.emit} to {args.output}")
    else:
        print(output)
    return 0


def cmd_summaries(args) -> int:
    index = _load(args)
    if index.callgraph is None:
        print("taint analysis disabled")
        return 0
    print(index.callgraph.dump())
    print()
    print("taint summaries")
    for name in sorted(index.summaries):
        print(f"  {index.summaries[name].describe()}")
    unmodelled = index.unmodelled_externals()
    if unmodelled:
        print()
        print(f"unmodelled external calls ({len(unmodelled)}): {', '.join(sorted(unmodelled))}")
    return 0


def cmd_specs(args) -> int:
    table = SpecTable()
    for spec in DEFAULT_REGISTRY.specs():
        table.add(spec)
    print(json.dumps(table.as_dicts(), indent=2))
    return 0


def cmd_slice(args) -> int:
    from .ai.slicer import slice_finding

    index = _load(args)
    if not index.findings:
        print("no findings to slice")
        return 0
    for position, finding in enumerate(index.findings, start=1):
        excerpt = slice_finding(finding, index)
        print(f"--- slice {position}/{len(index.findings)} "
              f"({excerpt.line_count} lines from {excerpt.enclosing_line_count}, "
              f"{excerpt.reduction * 100:.1f}% reduction)")
        print(excerpt.text)
        print()
    return 0


# --- argument parsing -------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="A security-aware C compiler: taint analysis over its own IR.",
    )
    parser.add_argument("--version", action="version", version=f"aegis {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("paths", nargs="+", help="C source files or directories")
        p.add_argument("--cpp", action="store_true", help="preprocess with the system gcc")
        p.add_argument("--no-taint", action="store_true", help="disable taint analysis")
        p.add_argument("--no-memory", action="store_true", help="disable the heap state machine")
        return p

    audit = common(sub.add_parser("audit", help="run the full pipeline and report findings"))
    audit.add_argument(
        "--format", choices=["console", "table", "json", "sarif"], default="console"
    )
    audit.add_argument("-o", "--output", help="write the report to a file")
    audit.add_argument(
        "--fail-on",
        choices=["error", "warning", "note"],
        default="error",
        help="minimum severity that sets a non-zero exit code",
    )
    audit.add_argument(
        "--adjudicate",
        action="store_true",
        help="review each finding through the configured model (falls back to "
             "the deterministic path when no key is set)",
    )
    audit.add_argument(
        "--model", help="override the review model for this run (free-only mode refuses non-free ids)"
    )
    audit.add_argument(
        "--no-ai-cache", action="store_true", help="bypass the adjudication cache"
    )
    audit.add_argument(
        "--ai-workers", type=int, default=4, metavar="N",
        help="concurrent adjudication requests (default 4)",
    )
    audit.set_defaults(func=cmd_audit)

    ir = common(sub.add_parser("ir", help="dump three-address code in SSA form"))
    ir.set_defaults(func=cmd_ir)

    cfg = common(sub.add_parser("cfg", help="dump the control flow graph"))
    cfg.add_argument("--function", help="restrict output to one function")
    cfg.add_argument("--dot", action="store_true", help="emit Graphviz DOT")
    cfg.set_defaults(func=cmd_cfg)

    dataflow = common(
        sub.add_parser("dataflow", help="run reaching definitions and live variables")
    )
    dataflow.add_argument("--function", help="restrict output to one function")
    dataflow.set_defaults(func=cmd_dataflow)

    summaries = common(
        sub.add_parser("summaries", help="dump the call graph and interprocedural summaries")
    )
    summaries.set_defaults(func=cmd_summaries)

    build = common(sub.add_parser("build", help="generate code via LLVM"))
    build.add_argument(
        "--emit", choices=["llvm", "asm", "obj"], default="llvm", help="output form"
    )
    build.add_argument("-o", "--output", help="write to a file instead of stdout")
    build.add_argument("--opt", type=int, default=2, choices=[0, 1, 2, 3], help="optimisation level")
    build.add_argument("--run", metavar="FUNCTION", help="JIT-compile and call this function")
    build.add_argument("--force", action="store_true", help="generate despite type errors")
    build.set_defaults(func=cmd_build)

    sl = common(sub.add_parser("slice", help="render each finding as a minimal excerpt"))
    sl.set_defaults(func=cmd_slice)

    specs = sub.add_parser("specs", help="print the taint specification table")
    specs.set_defaults(func=cmd_specs)

    ai = sub.add_parser("ai", help="show how adjudication is configured")
    ai.add_argument("--check", action="store_true",
                    help="spend one request to verify the key and model work")
    ai.add_argument("--models", action="store_true",
                    help="list the models this key can reach (OpenRouter)")
    ai.add_argument("--model", help="check a specific model")
    ai.add_argument("--role", choices=["review", "interactive"], default="review",
                    help="which use case to show or check (default: review)")
    ai.add_argument("--json", action="store_true", help="machine-readable output")
    ai.set_defaults(func=cmd_ai)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Prefer UTF-8 output where the terminal allows it; the renderer falls back
    # to ASCII glyphs on its own if this fails (older Windows consoles).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError, ValueError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
