# The Prahari compiler

> Sources live in [`compiler/`](../compiler). Run every command below from there.

**A security-aware C compiler whose own dataflow analyses drive CWE detection.**

Prahari compiles a subset of C through a complete front end — lexing and parsing,
semantic analysis, three-address IR, SSA construction, control flow graphs — and
then reuses that machinery as a static application security testing engine. The
compiler is not scaffolding around the analysis; the analysis *is* the compiler's
dataflow framework, instantiated four times.

Results are emitted as [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), so
they render in VS Code, upload to GitHub code scanning, and interoperate with
any tool that speaks the standard.

```console
$ prahari audit examples/cmd_injection.c

● CWE-78: OS Command Injection · ERROR · prahari/cwe78 · [3/3]
  Untrusted data reaches system() at argument 0 after 4 propagation step(s)
  with no sanitisation on the path, allowing shell command injection.

  ● SOURCE    examples/cmd_injection.c:10  int main(int argc, char **argv) {
  │                                  parameter is attacker-controlled
  ▼
  ○ PROPAGATE examples/cmd_injection.c:17  strcpy(host, argv[1]);
  │                                  read from tainted storage, then propagated by strcpy()
  ▼
  ○ PROPAGATE examples/cmd_injection.c:18  build_command(host, cmd);
  │                                  build_command: param0 -> param1; no sanitisation
  ▼
  ● SINK      examples/cmd_injection.c:19  system(cmd);
  │                                  argument is executed by the shell

  GUARDS ON PATH   if (argc < 2) { (line 14)
  MISSING CONTROL  input validation or an allowlist before the command is executed
  SUGGESTED FIX    Replace system()/popen() with execve() and an explicit argument array…
```

---

## Why this design

A compiler already computes everything a precise security analysis needs —
symbol resolution, SSA renaming, control flow, interprocedural dataflow. Tools
that work on token streams or embeddings re-derive that information badly. Prahari
keeps it.

The consequence is visible in the trace above. Prahari does not report
`system()` because the name looks dangerous. It reports it because it can show
that the value arriving there originated in `argv`, survived a `strcpy`, crossed
a function boundary whose summary says `param0 -> param1`, and met no sanitizer
on the way. `examples/safe.c` contains `strcpy`, `system` and `malloc` and
produces **zero** findings, because none of them are reachable from untrusted
data or missing a control.

---

## Install

```bash
pip install -e .          # runtime deps: pycparser, networkx
pip install -e ".[dev]"   # plus pytest
```

```bash
pip install -e ".[codegen]"   # plus llvmlite, for code generation
```

Python 3.10+. No C toolchain is required to *analyse* code — the preprocessor is
self-contained. A linker is needed only to turn generated object files into
executables.

## Use

```bash
prahari audit src/                        # human-readable report
prahari audit src/ --format table         # one line per finding, for CI logs
prahari audit src/ --format sarif -o out.sarif
prahari audit src/ --fail-on warning      # exit 1 on warnings too
```

Exit codes: `0` clean · `1` findings at or above the threshold · `2` usage error.

Every compiler phase is inspectable on its own:

| Command | Output |
|---|---|
| `prahari ir <path>` | three-address code in SSA form |
| `prahari cfg <path> [--dot]` | basic blocks, edges, predecessors — or Graphviz |
| `prahari dataflow <path>` | reaching definitions, live variables, dead stores |
| `prahari summaries <path>` | call graph and interprocedural taint summaries |
| `prahari slice <path>` | each finding as a minimal source-to-sink excerpt |
| `prahari specs` | the taint specification table as JSON |
| `prahari build <path> --emit llvm\|asm\|obj` | generate code via LLVM |
| `prahari build <path> --run <fn>` | JIT-compile and call a function |

---

## Architecture

```
  C source
     │  frontend/preprocess.py    self-contained cpp: includes, macros, comments
     │  frontend/adapter.py       pycparser c_ast ──► PrahariAST   ← the only reuse boundary
     ▼
  PrahariAST
     │  semantic/                 scope tree, type checking, diagnostics
     │  ir/lowering.py            three-address code, explicit control flow
     │  ir/cfg.py                 basic blocks, dominators, dominance frontiers
     │  ir/ssa.py                 phi placement (Cytron), renaming, pruning
     ▼
  SSA-form CFG
     │
     │  analysis/framework.py     ◄── ONE generic worklist solver
     │      ├─ reaching_defs.py       forward · set · union
     │      ├─ live_vars.py           backward · set · union
     │      ├─ taint.py               forward · set · union      → CWE-78/120/134
     │      └─ memory.py              forward · map of states    → CWE-476/416/415/401
     │  analysis/callgraph.py     bottom-up summaries over the call graph
     ▼
  Semantic Index ──► detectors/ ──► report/sarif.py · report/console.py

  ir/lowering.py output ──► codegen/llvm_emitter.py ──► LLVM IR · object · JIT
```

**The solver is written once.** It knows about blocks, edges, a lattice and a
transfer function — nothing about taint, liveness or the heap. Adding a weakness
class costs a transfer function and a description, not an engine.

### The four instantiations

| Analysis | Direction | Lattice | Purpose |
|---|---|---|---|
| Reaching definitions | forward | set, union | validates the framework against a known answer |
| Live variables | backward | set, union | dead-store detection; proves direction-independence |
| Taint propagation | forward | set, union | CWE-78, CWE-120, CWE-134 |
| Heap state machine | forward | map → flat states | CWE-476, CWE-416, CWE-415, CWE-401 |

The framework also supports **edge transfer functions**, which two of these
genuinely require: live variables needs phi operands treated as live on their
own incoming edge, and taint needs a guard to remove taint only on the edge into
its true branch.

### Code generation

The same IR the analyses run on is lowered to LLVM IR, and from there to native
object code or JIT execution. Remove every analysis and a working compiler
remains — literally:

```console
$ prahari build prog.c --emit obj -o prog.o && gcc prog.o -o prog && ./prog
fib: 0 1 1 2 3 5 8 13 21 34
gcd(1071,462) = 21
```

Two decisions worth naming. **Codegen consumes the pre-SSA instruction list**,
not the SSA form: every local becomes an `alloca` and LLVM's own `mem2reg`
builds its SSA, so two renaming schemes never have to be reconciled. And
**function signatures are declared in a first pass before any body is emitted**,
which is what makes mutual recursion work — the case where a caller must bind to
a callee that does not exist yet.

The test suite JIT-compiles and *executes* the generated code and checks the
answers (loops, `switch`, arrays, short-circuit operators, recursion, mutual
recursion), because verifying that IR merely parses proves nothing about
correctness.

---

## Results

Full method, corpora and caveats in [RESULTS.md](RESULTS.md). Every
number is regenerated by `python eval/ablation.py` and asserted in
`tests/test_eval.py`, so published figures cannot silently drift.

**The ablation matrix.** Each row adds exactly one component, so the change
between adjacent rows is attributable to that component alone:

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

Rows 2→3 isolate interprocedural analysis (+6.7 pp detection at no precision
cost). Rows 3→4 isolate the heap state machine, which covers the four
memory-safety classes taint analysis structurally cannot see. Row 5 is the
control: with no model configured it must reproduce row 4 exactly, and a test
asserts it does.

**On the perfect score.** A 100% result on a corpus generated from templates the
tool already handles proves the harness works, not that the analyser is good.
A second, hand-written corpus (`eval/corpus_hard`) targets the documented
limitations instead, and reports **100% detection at 10% FPR** — one honest
false positive, a bounds-checked `strcpy` that the analysis cannot clear because
it does not evaluate `sizeof`. Writing that corpus surfaced two real bugs
against the project's own stated model (globals not carried through summaries;
struct members loaded as values instead of passing the base object), both fixed.

No comparison is made to IRIS, vEcho or any published tool: those run on
real-world Java CVEs with frontier models, and Prahari runs on a synthetic C
subset. See [RESULTS.md §4](RESULTS.md) for what these numbers do and
do not support.

---

## Detection

| CWE | Name | Strategy |
|---|---|---|
| 78 | OS Command Injection | tainted value reaches `system`/`popen`/`exec*` |
| 120 | Buffer Copy without Size Check | tainted or unbounded source into `strcpy`/`strcat`/`sprintf`/`gets` |
| 134 | Externally-Controlled Format String | tainted value in the format position (per-function index) |
| 476 | NULL Pointer Dereference | allocation dereferenced in state `ALLOCATED` — never NULL-checked |
| 416 | Use After Free | any use of an allocation in state `FREED` |
| 415 | Double Free | `free` of an allocation already in state `FREED` |
| 401 | Memory Leak | allocation live at exit whose ownership never escaped |

Taint is keyed on **SSA definitions** where possible, so a tainted value and a
later safe value of the same variable never merge. Allocations are keyed on
**allocation site**, not variable name, so `q = p; free(q);` correctly frees
`p`'s allocation and aliases are not double-counted.

### Interprocedural analysis

Summary-based, not inlining. Each function is analysed once per parameter,
producing a description of how taint flows through it:

```console
$ prahari summaries examples/cmd_injection.c
build_command: param0 -> param1; param0 -> CWE-120 sink; no sanitisation
```

Summaries are computed in reverse topological order of the call graph, so a
callee is always summarised before its callers. Recursive components iterate to
fixpoint from an optimistic empty summary, under an iteration cap.

---

## Scope and limitations

Stated deliberately, because an unstated limitation invalidates a result while a
quantified one strengthens it.

**Excluded from the analysed subset**, recorded per occurrence and reported in
the exclusion log: `goto` and labels, function pointers, unions, variadic *user*
functions, indirect calls.

**Modelling limitations:**

- **No points-to analysis.** Memory is modelled field-insensitively, per base
  variable. Aliasing through struct fields or arrays of pointers is not tracked.
- **Heap reasoning is intraprocedural.** An allocation passed to another
  function is treated as having escaped — conservative in the direction of
  fewer false positives.
- **`sizeof` is not evaluated**, so CWE-120 fires on the absence of a bound
  rather than on a comparison between a length and a capacity.

`prahari audit` prints the exclusion count grouped by reason, and
`index.stats["unmodelled_externals"]` counts the external calls the analysis had
no specification for — the honest measure of how much it had to guess.

---

## The model layer

Prahari ships with **no language model configured and no network access.** The
full pipeline — parse, IR, SSA, dataflow, taint, detectors, SARIF — runs and
produces every finding above deterministically.

The seam exists: `ai/gateway/` defines a provider-agnostic interface,
`ai/slicer.py` renders a finding as a minimal source-to-sink excerpt, and
`ai/adjudicator.py` can review candidates through a gateway. The shipped
implementation is `NullGateway`, which is a permanent component rather than a
placeholder:

1. the system works, and demos, with no model at all;
2. it is the **control configuration** — comparing any future adjudicator
   against it is what isolates a model's contribution from the static
   analysis's;
3. it makes CI deterministic, which model output is not.

An adjudicator may lower a finding's confidence or mark it unexploitable. It can
never invent one. Detection stays a property of the program analysis.

---

## Development

```bash
python -m pytest              # 210 tests
python -m pytest -v -k ssa    # one area
python eval/harness.py        # detection rate and FPR
python eval/ablation.py       # the ablation matrix
```

The suite cross-checks the hand-written dominance frontier computation against
networkx's independent implementation on every test program, and asserts the SSA
single-assignment invariant after every build.

```
src/prahari/
├── frontend/    preprocess · adapter · ast_nodes      ← pycparser boundary
├── semantic/    symbol_table · types · checker
├── ir/          instructions · lowering · cfg · ssa
├── analysis/    lattice · framework · reaching_defs · live_vars
│                taint · memory · callgraph · specs · detectors/
├── ai/          gateway/ · slicer · adjudicator
├── codegen/     llvm_emitter  (three-address IR → LLVM IR → object/JIT)
├── report/      sarif · console
├── index.py     the Semantic Index
└── cli.py

eval/
├── corpus_gen.py   generates the paired corpus from templates
├── corpus/         30 cases: 7 CWEs x 5 flow variants
├── corpus_hard/    10 hand-written cases targeting documented limitations
├── harness.py      Juliet-convention ground truth and scoring
└── ablation.py     the configuration matrix
```

The harness reads NIST Juliet's conventions (`CWE<n>_` filenames, `bad`/`good`
function naming), so pointing it at the real SARD suite requires no code
changes — only a path.

## Licence

MIT. Reused components and their licences are listed in
[ATTRIBUTION.md](ATTRIBUTION.md).
