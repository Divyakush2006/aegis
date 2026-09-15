# Results

All numbers in this document are produced by `python eval/ablation.py` and
`python eval/harness.py`, and are asserted as regression tests in
`tests/test_eval.py`. **The evaluation is run with no model configured**, so
every configuration below is deterministic and reproducible from the
repository. Adjudication exists and works (see [AI.md](AI.md)); it is switched
off here deliberately, for the reason row 5 explains.

All commands run from `compiler/`.

```bash
python eval/corpus_gen.py           # regenerate the corpus (deterministic)
python eval/harness.py              # detection rate, FPR, per-CWE breakdown
python eval/ablation.py             # the ablation matrix
python eval/harness.py eval/corpus_hard
```

---

## 1. Method

### Ground truth

The corpus follows the NIST Juliet conventions, so the same harness scores it
and the real SARD suite with no special casing:

- the expected weakness comes from the `CWE<n>_` filename prefix;
- a function named `bad*` contains the flaw;
- a function named `good*` is the safe counterpart.

Juliet's two safe forms are both used. **goodG2B** replaces the untrusted
source with a safe value, testing that the tool does not fire on the mere
presence of a dangerous call. **goodB2G** keeps the untrusted source and fixes
the sink, testing that sanitizers and bounded primitives are recognised.

### Scoring is per function, not per file

Each file contains both the flawed and the safe variant. Scoring per file would
make every case simultaneously a true positive and a false positive. Per-function
scoring is what yields a detection rate *and* a false positive rate from one
corpus — the property that makes paired suites worth using at all.

Findings raised inside a helper are attributed to the `bad`/`good` root that
reaches them, resolved through the call graph. Attributing a finding to
`sink_bad` rather than to `bad` would score a correct cross-function detection
as a miss.

### Corpora

| Corpus | Cases | Scored functions | Purpose |
|---|---:|---:|---|
| `eval/corpus` | 30 | 72 | 7 weakness classes × 5 flow variants, generated from templates |
| `eval/corpus_hard` | 10 | 20 | hand-written, targeting documented limitations |

Flow variants mirror the Juliet scheme, expressing the same weakness through
progressively more indirect structure: `01` baseline, `02` control-dependent,
`03` loop-carried, `04` nested control, `05` interprocedural.

---

## 2. The ablation matrix

Each row adds exactly one component to the row above, so the change between
adjacent rows is attributable to that component and nothing else.

**Main corpus (30 cases, 72 scored functions):**

| Configuration | TP | FP | FN | TN | Detection | FPR | Precision | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Pattern matching only | 20 | 29 | 10 | 13 | 66.7% | 69.0% | 40.8% | 0.51 |
| + intraprocedural taint | 12 | 0 | 18 | 42 | 40.0% | 0.0% | 100.0% | 0.57 |
| + interprocedural summaries | 14 | 0 | 16 | 42 | 46.7% | 0.0% | 100.0% | 0.64 |
| + heap state machine | 30 | 0 | 0 | 42 | **100.0%** | **0.0%** | **100.0%** | **1.00** |
| + adjudication (NullGateway) | 30 | 0 | 0 | 42 | 100.0% | 0.0% | 100.0% | 1.00 |

**Hard corpus (10 cases, 20 scored functions):**

| Configuration | TP | FP | FN | TN | Detection | FPR | Precision | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Pattern matching only | 9 | 9 | 1 | 1 | 90.0% | 90.0% | 50.0% | 0.64 |
| + intraprocedural taint | 5 | 1 | 5 | 9 | 50.0% | 10.0% | 83.3% | 0.62 |
| + interprocedural summaries | 7 | 1 | 3 | 9 | 70.0% | 10.0% | 87.5% | 0.78 |
| + heap state machine | 10 | 1 | 0 | 9 | 100.0% | 10.0% | 90.9% | 0.95 |
| + adjudication (NullGateway) | 10 | 1 | 0 | 9 | 100.0% | 10.0% | 90.9% | 0.95 |

### Reading the table

**Row 1 is the comparison that matters.** Pattern matching reports every call to
a dangerous function by name — using the *same parser* and the *same
specification table* as every other row, and nothing else. It is the "grep for
`strcpy`" baseline. Its 69% false positive rate on the main corpus, and 90% on
the hard corpus, is what a name-based linter costs a developer.

Adding dataflow analysis takes that to **0%**. That is the project's central
claim, measured rather than asserted: the compiler's own dataflow machinery is
what converts a detector into a precise one.

**Rows 2→3 isolate interprocedural analysis.** Call-graph summaries add 2 true
positives on the main corpus (+6.7 pp detection) and 2 on the hard corpus
(+20 pp), with no precision cost. These are exactly the flow-variant `05` cases
and the return-chain case, where the source and sink are in different functions.

**Rows 3→4 isolate the heap state machine.** It accounts for the memory-safety
classes (CWE-476, 416, 415, 401) that taint analysis structurally cannot see.
The jump is large because four of seven weakness classes live there.

**Row 5 is the control.** Adjudication through `NullGateway` reproduces row 4
exactly, which is the definition of a control: an adjudicator is measured as a
delta against this row, so a model's contribution can never be confused with the
analysis's. `tests/test_eval.py` asserts the two rows are identical.

A live adjudicated row is deliberately **absent** from this table. Producing one
would need a credential, which makes the number unreproducible for anyone
reading this document, and it would fold a model's behaviour into a table whose
entire purpose is to attribute results to compiler components. The
infrastructure to run that experiment is in place — `eval/mock_model.py` proves
the path end to end without a credential — and the design guarantees the
direction of any such delta: adjudication may only demote, so it can cost
detection and can only improve precision. It can never be what produced row 4.

That experiment is `eval/model_bench.py`. It runs each candidate model over both
corpora, scores the result with this document's function-level method, and
reports it beside a `static` control — separately from this table, because its
numbers depend on a credential and a model version that a reader cannot pin.

---

## 3. Per-weakness results (full configuration, main corpus)

| CWE | TP | FP | FN | TN | Detection | FPR | Precision |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-78 OS Command Injection | 5 | 0 | 0 | 9 | 100.0% | 0.0% | 100.0% |
| CWE-120 Buffer Overflow | 5 | 0 | 0 | 9 | 100.0% | 0.0% | 100.0% |
| CWE-134 Format String | 4 | 0 | 0 | 8 | 100.0% | 0.0% | 100.0% |
| CWE-401 Memory Leak | 4 | 0 | 0 | 4 | 100.0% | 0.0% | 100.0% |
| CWE-415 Double Free | 4 | 0 | 0 | 4 | 100.0% | 0.0% | 100.0% |
| CWE-416 Use After Free | 4 | 0 | 0 | 4 | 100.0% | 0.0% | 100.0% |
| CWE-476 NULL Dereference | 4 | 0 | 0 | 4 | 100.0% | 0.0% | 100.0% |

Detection holds at 100% across every flow variant, including the interprocedural
one — asserted per variant in `tests/test_eval.py`.

---

## 4. Honest reading of these numbers

**A perfect score on a self-built corpus is not evidence that the analyser is
good.** It is evidence that the harness works and that the corpus is within the
analysed subset. This is the benchmark-inflation problem: a generated corpus
built from templates the tool already handles will flatter any tool.

The hard corpus exists for exactly this reason. It is hand-written against the
*documented limitations* rather than against the implementation, and it is where
the real behaviour shows:

| Hard case | Outcome | Why |
|---|---|---|
| Taint through a file-scope global | detected | fixed during evaluation — summaries now carry global effects |
| Taint through a struct field | detected | fixed during evaluation — members pass the base object |
| Bounds-checked `strcpy` | **false positive** | `sizeof` is not evaluated; the guard is not connected to capacity |
| Ownership released in a helper | correct (no leak) | passing a pointer to any function is treated as an escape |
| Freed on one path, used after | detected | the join takes `FREED` |
| Sanitised on one path only | detected | union join keeps taint from the unsanitised path — correct for a "may" analysis |
| Taint through three return levels | detected | summaries compose |
| Format string via pointer alias | detected | SSA copy propagation |
| NULL check *after* the dereference | detected | the state machine is flow-sensitive |
| Taint through an array of pointers | detected | field-insensitive memory model over-approximates |

Two of these were genuine bugs *against the project's own stated model* rather
than limitations, and were fixed: globals were not carried through summaries,
and a struct member passed to a function was loaded as a value instead of
passing the base object. Both were found only because the hard corpus existed.

**The one remaining false positive is real and is not worked around.**
`strcpy(dest, data)` guarded by `if (strlen(data) < 64)` is reported, because
the analysis does not evaluate `sizeof` and so cannot relate the guard to the
destination's capacity. Suppressing it by pattern-matching the guard would make
the number look better and the tool worse.

### What these numbers do *not* support

- **No comparison to published tools.** IRIS (45.8% detection / 84.8% FPR) and
  vEcho (65% / 59.8%) operate on real-world Java CVEs with frontier models.
  Prahari runs on a synthetic C subset. Those figures are context for how hard the
  problem is, not a scoreboard.
- **No claim about real-world code.** Every case here is within the documented
  subset. The exclusion log is empty on this corpus precisely because the corpus
  was built to be inside it.
- **No claim about a language model's contribution.** No model is configured for
  any number in this document. Row 5 establishes the control such a claim would
  need, and `eval/check_invariants.py` is the gate that would keep a future
  adjudicated run honest: it fails the build if adjudication changes which
  findings exist, raises a confidence, or alters a severity.

The next step that would make these numbers externally meaningful is running the
real NIST Juliet suite, filtered to flow variants `01`/`02` (the higher variants
inject `goto`, function pointers and cross-file flows that the documented subset
excludes), and reporting the exclusion rate alongside the detection rate. The
harness needs no changes to do this — it already reads Juliet's conventions.

---

## 5. Performance

| Metric | Value |
|---|---|
| Main corpus, 30 files, full pipeline | 0.28 s |
| Hard corpus, 10 files | 0.10 s |
| Ablation matrix, 5 configurations × 30 files | ~1.4 s |
| Full test suite (210 tests) | 6.6 s |
| SSA invariant violations across all corpora | 0 |
| Declarations excluded from the analysed subset | 0 |
| External calls with no specification | 0 |

Summary computation is bottom-up over the call-graph condensation, so cost is
linear in the number of functions rather than exponential in call depth.
Recursive components iterate to fixpoint under an 8-round cap; mutual recursion
is covered by `tests/test_analysis.py`.

---

## 6. Reproducing

```bash
pip install -e ".[dev]"
python -m pytest                 # 210 tests, including every number above
python eval/ablation.py          # regenerates the tables in section 2
```

Or, hermetically:

```bash
# from the repository root
docker build -t prahari .          # runs the test suite as part of the build
docker run --rm -v "$PWD:/work" prahari audit /work --format sarif
```
