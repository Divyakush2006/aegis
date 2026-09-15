<div align="center">

# Prahari

**A security-aware C compiler, and an IDE built around it.**

[![CI](https://github.com/Divyakush2006/prahari/actions/workflows/ci.yml/badge.svg)](https://github.com/Divyakush2006/prahari/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-371%20passing-brightgreen)](compiler/tests)
[![Python](https://img.shields.io/badge/python-3.10%20–%203.13-blue)](compiler/pyproject.toml)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-informational)](docs/RESULTS.md)
[![IDE](https://img.shields.io/badge/IDE-desktop%20%2B%20browser-8A2BE2)](ide/README.md)
[![Licence](https://img.shields.io/badge/licence-MIT-green)](#licence)

*Seven CWE classes · 0% false positives on the evaluation corpus · LLVM backend · desktop IDE*

</div>

---

Prahari compiles a subset of C through a complete front end — preprocessing,
parsing, semantic analysis, three-address IR, SSA construction, control flow
graphs — and then reuses that same machinery as a static application security
testing engine.

The compiler is not scaffolding around the analysis. **The analysis *is* the
compiler's dataflow framework, instantiated four times.** That is the claim this
repository exists to demonstrate, and [the measured results](#measured-results)
are how it is defended: the same parser and the same specification table, with
the dataflow analysis switched off, produce a **69% false positive rate**. With
it, **0%**.

```
prahari/
├── compiler/     Python — the compiler, the analyses, the language server
├── ide/          TypeScript — the IDE, as a desktop program and in the browser
└── docs/         architecture, method, results, attribution, planning record
```

### Contents

[What it does](#what-it-does) · [Why it is not a linter](#why-it-is-not-a-linter) ·
[Measured results](#measured-results) · [Architecture](#architecture) ·
[Quick start](#quick-start) · [The IDE](#the-ide) · [Coverage](#coverage) ·
[Command reference](#command-reference) · [AI adjudication](#ai-adjudication-optional) ·
[Engineering](#engineering) · [Documentation](#documentation) ·
[Scope and limitations](#scope-and-limitations)

---

## What it does

```console
$ prahari audit examples/cmd_injection.c

● CWE-78: OS Command Injection · ERROR · prahari/cwe78

  ● SOURCE    cmd_injection.c:10  int main(int argc, char **argv) {
  │                               parameter is attacker-controlled
  ▼
  ○ PROPAGATE cmd_injection.c:17  strcpy(host, argv[1]);
  │                               read from tainted storage, then propagated by strcpy()
  ▼
  ○ PROPAGATE cmd_injection.c:18  build_command(host, cmd);
  │                               build_command: param0 -> param1; no sanitisation
  ▼
  ● SINK      cmd_injection.c:19  system(cmd);
  │                               argument is executed by the shell

  GUARDS ON PATH   if (argc < 2) { (line 14)
  MISSING CONTROL  input validation or an allowlist before the command is executed
```

It does not report `system()` because the name looks dangerous. It reports it
because it can show where the value came from, every function it crossed, what
the compiler's interprocedural summary said about each hop, and which guards
already stand on the path.

`compiler/examples/safe.c` contains `strcpy`, `system` and `malloc` and produces
**zero** findings.

And it is a real compiler — the same IR feeds LLVM:

```console
$ prahari build prog.c --emit obj -o prog.o && gcc prog.o -o prog && ./prog
fib: 0 1 1 2 3 5 8 13 21 34
gcd(1071,462) = 21
```

---

## Why it is not a linter

A linter matches patterns over syntax. Prahari answers a different question —
*can attacker-controlled data reach this operation, and is anything stopping it?*
— and it can only answer that because the compiler already built the structures
the question needs:

| The question | What answers it | Built by |
|---|---|---|
| Which definition reaches this use? | reaching definitions | the dataflow framework |
| Is this value still live here? | live variables | the dataflow framework |
| Did this value come from an attacker? | taint propagation | the dataflow framework |
| Is this pointer freed, null, or valid? | heap state machine | the dataflow framework |

One generic worklist solver with edge transfer functions serves all four. It
knows about blocks, edges, a lattice and a transfer function — and nothing about
taint, liveness or the heap. **Adding a weakness class costs a transfer function
and a description, not an engine.**

Across function boundaries, taint summaries are computed bottom-up over the call
graph's condensation, so `build_command(host, cmd)` is not a wall the analysis
stops at — it is a summary that says *parameter 0 flows to parameter 1,
unsanitised*.

---

## Measured results

Each row adds exactly one component, so the change between adjacent rows is
attributable to that component alone. Full method, corpus construction and
caveats in **[docs/RESULTS.md](docs/RESULTS.md)**.

| Configuration | Detection | FPR | Precision |
|---|---:|---:|---:|
| Pattern matching only *(the "grep for `strcpy`" baseline)* | 66.7% | **69.0%** | 40.8% |
| + intraprocedural taint | 40.0% | 0.0% | 100.0% |
| + interprocedural summaries | 46.7% | 0.0% | 100.0% |
| + heap state machine *(full static)* | **100.0%** | **0.0%** | **100.0%** |
| + adjudication (NullGateway) *(control)* | 100.0% | 0.0% | 100.0% |

Row 1 uses the same parser and the same specification table as every other row
and nothing else. The gap between it and row 4 is the measured answer to *what
does the dataflow analysis buy you*.

A second, hand-written corpus targeting the documented limitations reports
**100% detection at 10% FPR** — one honest false positive, kept rather than
suppressed, because suppressing it would make the number look better and the
tool worse. Writing that corpus surfaced two real bugs against the project's own
stated model, both fixed.

The final row is a control: it runs the entire adjudication pipeline with a
gateway that returns nothing, proving the AI layer changes no number unless a
model actually speaks.

---

## Architecture

```
   ┌───────────────────────────────────────────────────────┐
   │  ide/   Eclipse Theia (TypeScript)                     │
   │    desktop application  ·  browser application         │
   │    Monaco editor · findings panel · audit commands     │
   └───────────────────────┬───────────────────────────────┘
                           │  LSP over stdio
                           │  + prahari/findings notifications
   ┌───────────────────────▼───────────────────────────────┐
   │  compiler/   Python                                    │
   │                                                        │
   │   preprocess → adapter → PrahariAST                    │
   │        → semantic → IR → CFG → SSA                     │
   │              │                                         │
   │              ├── dataflow framework ─────┐             │
   │              │     reaching definitions  │             │
   │              │     live variables        │             │
   │              │     taint propagation     │             │
   │              │     heap state machine    │             │
   │              │                           ▼             │
   │              │                    detectors            │
   │              │                       │                 │
   │              │                       ├─→ adjudication (optional)
   │              │                       ▼                 │
   │              └── LLVM codegen    SARIF 2.1.0           │
   └───────────────────────────────────────────────────────┘
```

The **language server is the only interface** between the two languages. That
boundary is deliberate: the IDE speaks JSON-RPC and never learns what a lattice
is, and because the server speaks standard LSP, the compiler already works in
any other editor — Neovim, Emacs, VS Code — with no code written for them.

---

## Quick start

### The compiler

```bash
cd compiler
pip install -e ".[dev,codegen,lsp]"
python -m pytest                     # 371 tests
prahari audit examples --format table
python eval/ablation.py              # regenerates the table above
```

> If `prahari` is not found after installing, pip placed it in a per-user
> scripts directory that is not on your PATH (it prints the location). Add that
> directory to PATH, or use `python -m prahari.cli` wherever these docs say
> `prahari`.

No C toolchain is needed to *analyse* code — the preprocessor is self-contained.
A linker is needed only to turn generated object files into executables.

### The IDE, as a desktop application

```bash
cd ide
npm install
npm run build:desktop
npm run start:desktop                # opens in its own window
```

To launch it like any other installed program, without a terminal:

```powershell
powershell -ExecutionPolicy Bypass -File ide\scripts\Install-Shortcut.ps1 -Desktop
```

It then appears in the Start menu with its own icon and can be pinned to the
taskbar; `-Remove` deletes the shortcut again. Nothing is installed or copied —
the shortcut runs the build in this repository.

### The IDE, in a browser

```bash
cd ide
npm run build
npm start                            # http://127.0.0.1:3000
```

Both applications are assembled from the same extension and the same Theia
packages; they differ only in build target. Open a `.c` file in either and run
**Prahari: Audit Current File** (<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd>).

**No C++ toolchain or Visual Studio is required, on any platform.** This is a
deliberate property, not an accident — see [Engineering](#engineering).

### Reproducibly, in Docker

```bash
docker build -t prahari .
docker run --rm -v "$PWD/compiler/examples:/work" prahari
```

The image installs no C toolchain on purpose, runs the full test suite *during
the build* so a regression in detection rate breaks the image, and records the
ablation matrix in the build log for provenance. Credentials are configured at
run time and never baked into a layer.

---

## The IDE

Built on [Eclipse Theia](https://theia-ide.org/) 1.75 — which reuses the Monaco
editor and speaks LSP, so it looks and behaves like VS Code, but is a
vendor-neutral platform under the Eclipse Foundation rather than a fork. Prahari
needs a findings panel that renders multi-step dataflow traces, its own backend
service driving a Python compiler, and its own product identity; all three are
ordinary work in Theia and awkward-to-impossible in a VS Code extension.

**Nothing upstream is patched.** `prahari-ide` depends only on Theia's public
APIs, so upgrading Theia is a version bump.

| Command | Binding | Behaviour |
|---|---|---|
| **Prahari: Audit Current File** | <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd> | Full pipeline; fills the findings panel and the Problems view |
| **Prahari: Show Findings Panel** | — | Toggles the panel |
| **Prahari: Explain Function at Cursor** | — | CFG shape, call targets, interprocedural taint summary |
| **Prahari: Show Generated LLVM IR** | — | Runs the backend over the open file |
| **Prahari: Review Findings with AI** | — | Audits, then reviews each finding through the configured model |
| **Prahari: AI Adjudication Status** | — | Model, endpoint and key fingerprint — never the key |

LSP diagnostics can carry a message and a location; they cannot express *"this
value came from `argv`, crossed `strcpy`, then `build_command`, and arrived at
`system`"*. So findings travel over a custom `prahari/findings` notification
carrying the full trace, and the panel renders every step as a clickable row —
while the same findings are *also* mirrored into the Problems view and the
editor gutter, because a reviewer scanning code wants a squiggle and a reviewer
judging a report wants the trace.

C files open as **C**, not Plain Text: a Monarch tokenizer registered with Monaco
provides highlighting, comment toggling and bracket matching, and steps aside if
a VS Code C/C++ extension provides them instead. Go to File
(<kbd>Ctrl</kbd>+<kbd>P</kbd>) and Find in Files
(<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>F</kbd>) are backed by ripgrep.

Details, including how to extend it: **[ide/README.md](ide/README.md)**.

---

## Coverage

| CWE | Weakness | What decides it |
|---|---|---|
| **CWE-78** | OS command injection | taint reaches a sink argument (`system`, `popen`, `exec*`) with no sanitiser on the path |
| **CWE-120** | Buffer copy without checking size | taint reaches a copy whose destination the specification marks `unbounded_write` — so copying a constant into a fixed buffer is not reported |
| **CWE-134** | Externally-controlled format string | taint reaches the *format* argument, whose position the specification holds per function (`printf` 0, `fprintf` 1, `snprintf` 2) |
| **CWE-476** | NULL pointer dereference | heap state machine: dereferenced while `ALLOCATED`, never compared against NULL (which would move it to `CHECKED`) |
| **CWE-415** | Double free | heap state machine: a second release of the same allocation |
| **CWE-416** | Use after free | heap state machine: used while `FREED` — keyed by allocation site, so freeing through one alias and using through another is still caught |
| **CWE-401** | Memory leak | allocation still live at function exit **and** ownership never escaped: not returned, not stored where the caller can reach it, not passed on |

**Detectors own no analysis.** Each one is metadata and rendering over one of two
inputs — a taint sink hit, or a heap state machine event — which is precisely why
adding a weakness class costs a specification entry and a description rather than
a new engine. The three exclusions on CWE-401 matter more than the detection
itself: a leak checker that flags every allocation not freed in its own function
condemns correct ownership-transferring code, which is the fastest way to make
developers abandon a tool.

`--format sarif` emits SARIF 2.1.0 with `codeFlows`/`threadFlows`, so findings
render natively in GitHub code scanning — including Prahari's findings on its own
example corpus, which CI uploads on every push. Exit codes follow CI convention:
`0` clean, `1` findings at or above the threshold, `2` usage error.

---

## Command reference

| Command | What it shows |
|---|---|
| `prahari audit PATH` | findings, with full path traces |
| `prahari ir PATH` | three-address code in SSA form |
| `prahari cfg PATH --dot` | the control flow graph |
| `prahari dataflow PATH` | reaching definitions, live variables, dead stores |
| `prahari summaries PATH` | the call graph and interprocedural taint summaries |
| `prahari build PATH --emit obj` | LLVM IR, assembly, or an object file |
| `prahari slice PATH` | each finding as a minimal excerpt |
| `prahari specs` | the taint specification table |
| `prahari ai [--check]` | adjudication configuration and live check |

Every phase is inspectable on its own, which is what makes the pipeline
demonstrable rather than a black box that emits findings.

---

## AI adjudication *(optional)*

A language model can review findings the compiler has already produced. It is
strictly downstream of the verdict and may only **demote** — lower a confidence,
mark a path unexploitable, name a missing control.

```bash
cp .env.example .env                  # then set OPENROUTER_API_KEY=sk-or-...
cd compiler
prahari ai --check                    # one request; verifies key and model
python eval/model_bench.py --yes      # which model judges these findings best
prahari audit examples --adjudicate
```

Three invariants are enforced **in code**, not requested in a prompt:

| Invariant | What it prevents |
|---|---|
| No finding is created | a model inventing bugs |
| Confidence never rises | a weak result being talked up |
| Severity is never touched | a model changing CI outcomes |

So a broken or hostile model can cost recall, never precision. Each invariant has
a test named after it in `TestInvariants`, and a CI job re-proves them against a
deterministic mock endpoint with no credential present.

OpenRouter (`sk-or-…`) and Anthropic (`sk-ant-…`) keys both work; the provider is
detected from the key. **With OpenRouter it runs entirely on free models** — any
id without `:free` is refused before a request exists — and it treats the free
tier's daily allowance as a budget: paced under the per-minute limit,
content-addressed cache, cross-provider fallback chain, and a clean stop with the
reset time when the quota runs out. The default model was chosen in three stages
(published benchmarks, a live reachability probe, then a ground-truth benchmark
against this corpus), not by reputation.

**Without a key, everything above still runs.** The audit is identical, the
report says `model = null`, and CI stays deterministic — the unconfigured path is
the control row of the evaluation, not a degraded mode. The model sees a *slice*
(85.7% smaller than the enclosing file), never the repository, with absolute
paths stripped.

Try the whole live path with no credential at all:

```bash
python eval/mock_model.py --port 8787 &
PRAHARI_API_KEY=mock PRAHARI_API_BASE=http://127.0.0.1:8787 \
    prahari audit examples --adjudicate
```

Design, failure semantics and configuration: **[docs/AI.md](docs/AI.md)**.

---

## Engineering

**Continuous integration — nine jobs, every push:**

| Job | What it guards |
|---|---|
| Compiler (Python 3.10, 3.11, 3.12, 3.13) | the suite passes on every supported interpreter |
| IDE (TypeScript) | the extension typechecks, both applications bundle, Node drives the language server end to end |
| Ablation matrix | the corpus regenerates identically; detection and FPR hold |
| Adjudication (no credential required) | the demote-only invariants, and that no credential appears in any output |
| Self-scan and publish SARIF | Prahari audits its own corpus and uploads to code scanning |
| Reproducible output | two runs, and every file audited separately twice, must agree byte for byte |

**Determinism is a tested property.** The full static pipeline requires no
network and no model, and a CI job fails the build if two runs disagree.

**Security posture.** The key is never printed — only a fingerprint. Absolute
paths are stripped before anything leaves the machine. The compiler needs no
network; the IDE binds to loopback only. What leaves the machine, and what never
does, is documented in [SECURITY.md](SECURITY.md).

**Building without a C++ toolchain** is a property the project maintains
deliberately, because requiring the multi-gigabyte Visual Studio C++ workload to
open an editor is a real barrier. `ide/.npmrc` disables dependency install
scripts — which is also the conservative supply-chain posture, since an install
script is arbitrary code from every transitive dependency — and the build
substitutes pure-JavaScript stand-ins for the native modules that would otherwise
need compiling, *only where the native binary is absent*. A machine that has
compiled them keeps the real ones.

---

## Project scale

| | Files | Lines |
|---|---:|---:|
| Compiler, analyses, language server, AI gateways | 53 | 9,717 |
| Python tests (371, all passing) | 12 | 3,171 |
| Evaluation harness, model benchmark, CI gates | 7 | 2,034 |
| IDE extension (TypeScript / TSX) | 8 | 1,413 |
| IDE applications, build and tooling | 10 | 1,291 |
| C test cases and examples | 44 | 1,366 |
| Documentation | 12 | 3,344 |

---

## Documentation

| Document | What it covers |
|---|---|
| [docs/COMPILER.md](docs/COMPILER.md) | The compiler and analyses in depth |
| [docs/RESULTS.md](docs/RESULTS.md) | Evaluation method, ablation matrix, honest limitations |
| [docs/AI.md](docs/AI.md) | Adjudication: invariants, failure semantics, configuration |
| [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md) | What is reused, what is read, what is original |
| [ide/README.md](ide/README.md) | Building, running and extending the IDE |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, the checks to run, the properties every change must keep |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, and what leaves the machine |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/planning/](docs/planning/) | The original design record |

---

## Scope and limitations

Seven weakness classes, listed under [Coverage](#coverage).

Outside the analysed subset, recorded per occurrence and reported in the
exclusion log rather than silently skipped: `goto` and labels, function pointers,
unions, variadic *user* functions, indirect calls. There is no points-to
analysis — memory is modelled field-insensitively per base variable. `sizeof` is
not evaluated, which is the source of the one known false positive on the hard
corpus.

These are stated because a security tool that hides what it cannot see is worse
than one that names it.

---

## Contributing

Setup, the checks to run before a change, and the properties every change must
preserve are in [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerability reports:
[SECURITY.md](SECURITY.md).

## Licence

MIT — see [LICENSE](LICENSE). Reused components and their licences are listed in
[docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).

<div align="center">

*प्रहरी — **prahari**, a sentinel: something that stands watch.*

</div>
