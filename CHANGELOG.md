# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-09-15

The first complete release: compiler, analyses, evaluation, IDE and optional
AI review.

### Added

**Compiler**
- Self-contained C preprocessor, parser adapter and typed AST; unsupported
  constructs are recorded per declaration in an exclusion log rather than
  aborting the compilation.
- Three-address IR, control flow graphs, SSA construction with dominance
  frontiers and dead-phi pruning.
- One generic worklist dataflow framework with edge transfer functions,
  instantiated for reaching definitions, live variables, taint propagation and
  a heap state machine.
- Interprocedural taint summaries computed bottom-up over the call graph.
- Detectors for CWE-78, CWE-120, CWE-134, CWE-476, CWE-415, CWE-416 and CWE-401,
  each reporting the full source-to-sink path, the guards on it and the missing
  control.
- SARIF 2.1.0 output with code flows, console and table renderers, and CI exit
  codes.
- LLVM code generation (IR, assembly, object files, JIT) from the same IR.

**Evaluation**
- Juliet-convention harness with per-function scoring, a generated corpus and a
  hand-written hard corpus targeting documented limitations.
- Ablation matrix attributing results to individual analyses.
- Report-level gates for determinism and for the adjudication invariants.

**IDE**
- Eclipse Theia 1.75 application with an Aegis extension: findings panel with
  navigable path traces, Problems-view markers, explain-function and LLVM IR
  commands.
- Language server (pygls) providing diagnostics, symbol-table-filtered
  completion, hover and audit commands; works with any LSP client.
- C syntax highlighting, comment toggling and bracket-aware editing, with no
  plugin host or extra dependency.
- Go to File (Ctrl+P) and Find in Files (Ctrl+Shift+F), backed by ripgrep.
- `ide/browser-check.js`: drives the running IDE in headless Chrome and fails on
  any console error.
- Builds and runs with no C++ toolchain: dependency install scripts are off, and
  a pure-JS `drivelist` is substituted where the native module is absent.
- The Aegis shield icon, served as the application favicon.

**AI review (optional)**
- Adjudication that can only demote a finding, enforced in code and tested.
- OpenRouter and Anthropic gateways on a shared HTTP layer with retries, pacing,
  fail-fast quota handling, upstream-error classification and a
  content-addressed verdict cache.
- Free-only mode for OpenRouter, per-use-case model roles (`review`,
  `interactive`) and a cross-provider fallback chain.
- `aegis ai` status, live check and free-model catalogue; `eval/model_bench.py`
  ranks models against the corpus ground truth within the free daily quota.
- Defaults chosen by published benchmarks, a live reachability probe and the
  ground-truth benchmark, with the evidence in `docs/AI.md`.

### Fixed during development

- `Store.replace_uses` did not rename the pointer operand, which hid every
  use-after-free and NULL-dereference finding.
- The heap analysis keyed state by variable name instead of allocation site,
  double-counting aliases and missing use-after-free.
- Globals were not carried through interprocedural summaries, and struct
  members passed as call arguments lost their taint.
- Live-variable analysis leaked phi operands across every edge.
- The determinism CI job compared wall-clock timings and could never pass.
- The adjudication cache shared verdicts between roles running the same model
  at different reasoning effort.

[0.1.0]: https://github.com/Divyakush2006/aegis/releases/tag/v0.1.0
