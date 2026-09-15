<div align="center">

# Aegis

**A security-aware C compiler, and an IDE built around it.**

[![CI](https://github.com/Divyakush2006/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Divyakush2006/aegis/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-371%20passing-brightgreen)](compiler/tests)
[![Python](https://img.shields.io/badge/python-3.10%20–%203.13-blue)](compiler/pyproject.toml)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-informational)](docs/RESULTS.md)
[![Licence](https://img.shields.io/badge/licence-MIT-green)](#licence)

*Seven CWE classes · 0% false positive rate on the evaluation corpus · LLVM backend · Eclipse Theia IDE*

</div>

---

Aegis compiles a subset of C through a complete front end — preprocessing,
parsing, semantic analysis, three-address IR, SSA construction, control flow
graphs — and then reuses that same machinery as a static application security
testing engine.

The compiler is not scaffolding around the analysis. **The analysis *is* the
compiler's dataflow framework, instantiated four times.**

```
Compiler project/
├── compiler/     Python — the compiler, the analyses, the language server
├── ide/          TypeScript — the Theia-based development environment
└── docs/         architecture, attribution, results, and the planning record
```

---

## What it does

```console
$ aegis audit examples/cmd_injection.c

● CWE-78: OS Command Injection · ERROR · aegis/cwe78

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
$ aegis build prog.c --emit obj -o prog.o && gcc prog.o -o prog && ./prog
fib: 0 1 1 2 3 5 8 13 21 34
gcd(1071,462) = 21
```

---

## Results in one table

Each row adds exactly one component, so the change between adjacent rows is
attributable to that component alone. Full method and caveats in
[docs/RESULTS.md](docs/RESULTS.md).

| Configuration | Detection | FPR | Precision |
|---|---:|---:|---:|
| Pattern matching only *(the "grep for `strcpy`" baseline)* | 66.7% | **69.0%** | 40.8% |
| + intraprocedural taint | 40.0% | 0.0% | 100.0% |
| + interprocedural summaries | 46.7% | 0.0% | 100.0% |
| + heap state machine *(full static)* | **100.0%** | **0.0%** | **100.0%** |
| + adjudication (NullGateway) *(control)* | 100.0% | 0.0% | 100.0% |

Row 1 uses the same parser and the same specification table as every other row
and nothing else. The gap between it and row 4 is the measured answer to *what
does the dataflow analysis buy you*: a **69% false positive rate falls to 0%**.

A second, hand-written corpus targeting the documented limitations reports 100%
detection at 10% FPR — one honest false positive, kept rather than suppressed
because suppressing it would make the number look better and the tool worse.
Writing that corpus surfaced two real bugs against the project's own stated
model, both fixed.

---

## Quick start

### The compiler

```bash
cd compiler
pip install -e ".[dev,codegen,lsp]"
python -m pytest                     # 371 tests
aegis audit examples --format table
python eval/ablation.py              # regenerates the table above
```

No C toolchain is needed to *analyse* code — the preprocessor is self-contained.
A linker is needed only to turn generated object files into executables.

### The IDE

```bash
cd ide
npm install
npm run build
npm start                            # http://127.0.0.1:3000
```

Then open a `.c` file and run **Aegis: Audit Current File**
(<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd>).

No C++ toolchain or Visual Studio is needed, on Windows either. Theia's only
dependency that would compile C++ (`drivelist`, which ships no Windows binary)
is replaced at build time by a pure-JS implementation of the one function Theia
calls — and only where the native module is absent. `ide/.npmrc` keeps npm from
running dependency install scripts, which is what lets `npm install` succeed on a
stock machine.

---

## AI adjudication *(optional)*

A language model can review findings the compiler has already produced. It is
strictly downstream of the verdict and may only **demote** — lower a confidence,
mark a path unexploitable, name a missing control.

```bash
cp .env.example .env                  # then set OPENROUTER_API_KEY=sk-or-...
cd compiler
aegis ai --check                      # one request; verifies key and model
aegis ai --models                     # what the key can reach
python eval/model_bench.py --yes      # which model judges these findings best
aegis audit examples --adjudicate
```

OpenRouter (`sk-or-…`) and Anthropic (`sk-ant-…`) keys both work; the provider
is detected from the key. **With OpenRouter it runs entirely on free models** —
any id without `:free` is refused before a request exists — and it spends the
free tier's 50-requests-a-day as a budget: paced under the per-minute limit,
cached, and stopped cleanly with the reset time when the quota runs out.

The default, `nvidia/nemotron-3-ultra-550b-a55b:free`, was chosen in three
stages: published benchmarks, a live probe that removed the two strongest
models on paper (gated to other apps) and three congested ones, and a ground-truth
benchmark in which it was the only candidate to return a valid verdict for every
finding. The model is chosen by measurement, not reputation:
the benchmark scores each candidate against the corpus ground truth and ranks a
model that dismisses a real bug below one that costs more.

Three invariants are enforced in code rather than requested in a prompt:

| Invariant | What it prevents |
|---|---|
| No finding is created | a model inventing bugs |
| Confidence never rises | a weak result being talked up |
| Severity is never touched | a model changing CI outcomes |

So a broken or hostile model can cost recall, never precision. Each invariant
has a test named after it in `TestInvariants`.

**Without a key, everything above still runs.** The audit is identical, the
report says `model = null`, and CI stays deterministic — the unconfigured path
is the control row of the evaluation, not a degraded mode. The model sees a
*slice* (85.7% smaller than the enclosing files), never the repository, with
absolute paths stripped.

Full design, failure semantics and configuration: **[docs/AI.md](docs/AI.md)**.

Try the whole live path with no credential at all:

```bash
python eval/mock_model.py --port 8787 &
AEGIS_API_KEY=mock AEGIS_API_BASE=http://127.0.0.1:8787 \
    aegis audit examples --adjudicate
```

---

## How the pieces fit

```
   ┌──────────────────────────────────────────────┐
   │  ide/  Theia (TypeScript)                    │
   │    Monaco editor · findings panel · commands │
   └───────────────────┬──────────────────────────┘
                       │  LSP over stdio  +  aegis/findings notifications
   ┌───────────────────▼──────────────────────────┐
   │  compiler/  Python                           │
   │                                              │
   │   preprocess → adapter → AegisAST            │
   │        → semantic → IR → CFG → SSA           │
   │              │                               │
   │              ├── dataflow framework ─────┐   │
   │              │     reaching definitions  │   │
   │              │     live variables        │   │
   │              │     taint propagation     │   │
   │              │     heap state machine    │   │
   │              │                           ▼   │
   │              │                    detectors  │
   │              │                       │       │
   │              │                       ├─→ adjudication (optional)
   │              │                       ▼       │
   │              └── LLVM codegen    SARIF 2.1.0 │
   └──────────────────────────────────────────────┘
```

**One generic worklist solver** serves all four analyses. It knows about blocks,
edges, a lattice and a transfer function — nothing about taint, liveness or the
heap. Adding a weakness class costs a transfer function and a description, not
an engine.

The **language server is the only interface** between the two languages. That
boundary is deliberate: the IDE speaks JSON-RPC, never lattices, and because the
server speaks standard LSP it already works in any other editor.

---

## Command reference

| Command | What it shows |
|---|---|
| `aegis audit PATH` | findings, with full path traces |
| `aegis ir PATH` | three-address code in SSA form |
| `aegis cfg PATH --dot` | the control flow graph |
| `aegis dataflow PATH` | reaching definitions, live variables, dead stores |
| `aegis summaries PATH` | the call graph and interprocedural taint summaries |
| `aegis build PATH --emit obj` | LLVM IR, assembly, or an object file |
| `aegis slice PATH` | each finding as a minimal excerpt |
| `aegis specs` | the taint specification table |
| `aegis ai [--check]` | adjudication configuration |

Every phase is inspectable on its own, which is what makes the pipeline
demonstrable rather than a black box that emits findings.

`--format sarif` emits SARIF 2.1.0 with `codeFlows`/`threadFlows`, so findings
render natively in GitHub code scanning. Exit codes follow CI convention: `0`
clean, `1` findings at or above the threshold, `2` usage error.

---

## Project scale

| | Files | Lines |
|---|---:|---:|
| Compiler, analyses, language server, AI gateways | 53 | 9,717 |
| Python tests (371) | 12 | 3,171 |
| Evaluation harness, model benchmark, CI gates | 7 | 2,034 |
| IDE (TypeScript / TSX) | 7 | 1,215 |
| C test cases | 44 | 1,368 |
| Documentation | 7 | 2,546 |

---

## Documentation

| Document | What it covers |
|---|---|
| [docs/COMPILER.md](docs/COMPILER.md) | The compiler and analyses in depth |
| [docs/RESULTS.md](docs/RESULTS.md) | Evaluation method, ablation matrix, honest limitations |
| [docs/AI.md](docs/AI.md) | Adjudication: invariants, failure semantics, configuration |
| [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md) | What is reused, what is read, what is original |
| [ide/README.md](ide/README.md) | Building and extending the IDE |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, the checks to run, and the properties every change must keep |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, and what leaves the machine |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/planning/](docs/planning/) | The original design record |

---

## Scope

Seven weakness classes: **CWE-78** (command injection), **CWE-120** (buffer
overflow), **CWE-134** (format string), **CWE-476** (NULL dereference),
**CWE-415** (double free), **CWE-416** (use after free), **CWE-401** (memory
leak).

Outside the analysed subset, recorded per occurrence and reported in the
exclusion log: `goto` and labels, function pointers, unions, variadic *user*
functions, indirect calls. There is no points-to analysis — memory is modelled
field-insensitively per base variable. `sizeof` is not evaluated, which is the
source of the one known false positive.

The compiler requires no network and no model. The full static pipeline is
deterministic, and a CI job enforces that two runs produce byte-identical
output.

---

## Licence

MIT — see [LICENSE](LICENSE). Reused components and their licences are listed in
[docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).
