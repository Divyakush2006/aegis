# Adjudication

How Prahari uses a language model, and — more importantly — what it does not let
one do.

---

## The short version

The compiler is the detector. A model never decides that something is a
finding; it reviews a finding the dataflow analysis already proved and may
**lower** confidence, mark a path unexploitable, or name a missing control.

```
   taint analysis ─┐
                   ├─→ candidate findings ─→ [ adjudication ] ─→ report
   heap analysis  ─┘        (the compiler's)      (may demote)
```

Run it:

```bash
cp .env.example .env               # at the project root; set OPENROUTER_API_KEY=sk-or-...
cd compiler
prahari ai --check                   # one request, verifies key and model
prahari audit examples --adjudicate
```

With no key configured, every one of those still works. The audit runs, the
findings are identical, and the report says `model = null`. **An unconfigured
install is a working install** — that is a design constraint, not a fallback.

---

## Why this ordering

The project's claim is that its precision comes from program analysis. That
claim is only testable if the model cannot be the thing producing the numbers.
So the pipeline puts the model strictly downstream of the verdict, and three
invariants are enforced in code rather than requested in a prompt:

| Invariant | Where it lives | What it prevents |
|---|---|---|
| No finding is created | the pass iterates an existing list | a model inventing bugs |
| Confidence never rises | clamp to `[0,1]`, then `min(verdict, prior)` — an unstated prior counts as 1.0, the value the report shows | a weak result being talked up |
| Severity is never touched | ranking and exit codes read only static fields | a model changing CI outcomes |

The consequence is worth stating plainly: **a broken or hostile model can cost
recall, never precision.** For a security tool that is the correct direction to
fail, and it is why the measured numbers in [RESULTS.md](RESULTS.md) remain
attributable to the compiler.

Each invariant has a test named after it in
[`tests/test_ai.py`](../compiler/tests/test_ai.py), in `TestInvariants`.

---

## What the model actually sees

Not the file. A **slice**: the source-to-sink path, the interprocedural
summaries for the functions it crosses, and the guards already standing on it.

```
CANDIDATE: CWE-78 (OS Command Injection)

PATH:
  [SOURCE   ] cmd_injection.c:10    int main(int argc, char **argv) {
                                    parameter is attacker-controlled
  [PROPAGATE] cmd_injection.c:17    strcpy(host, argv[1]);
                                    read from tainted storage, then propagated by strcpy()
  [SINK     ] cmd_injection.c:19    system(cmd);
                                    argument is executed by the shell

FUNCTION SUMMARIES:
  build_command: param0 -> param1; no sanitisation

GUARDS ON PATH:
  if (argc < 2)  (line 14)
```

Measured context reduction on the example corpus is **85.7%** — the slice is a
seventh of the enclosing files. That number is reported in the adjudication
stats as `mean_context_reduction`, and it is the practical argument for slicing:
review context stays proportional to the defect rather than to the codebase.

Absolute paths are stripped before sending (`redact_paths`, on by default). The
file name is kept, because it appears in the finding; the directory layout of
the machine is not, because it is not evidence.

---

## Structured output, not parsed prose

The verdict comes back through a **forced tool call** whose `input_schema` is
the verdict schema:

```python
payload["tools"] = [{"name": "record_verdict", "input_schema": VERDICT_SCHEMA}]
payload["tool_choice"] = {"type": "tool", "name": "record_verdict"}
```

Asking for "JSON only" in a prompt yields JSON most of the time. Forcing a tool
yields an object the API itself validated. A response that contains neither
shape raises rather than guessing — a contract violation is a bug to surface,
not a value to invent.

---

## Failure is contained, not propagated

Every failure mode degrades to the static verdict:

| Situation | Result |
|---|---|
| No key configured | `NullGateway`; findings unchanged; `model = null` |
| Key rejected (401) | not retried; findings kept; `adjudicator = unavailable` |
| Rate limited (429) | retried with backoff, honouring `retry-after` |
| Transient 5xx | retried with exponential backoff and jitter |
| Endpoint unreachable | findings kept; the error is recorded and reported |
| Budget exhausted | remaining findings keep their static verdict |
| Unknown provider | `NullGateway` |

Jitter is not decoration: an audit adjudicates many findings concurrently, so a
synchronised retry storm is the realistic failure, not a hypothetical one.

A finding whose review failed is marked `unavailable` rather than silently
looking unreviewed — the distinction between *no one looked* and *someone
looked and agreed* is exactly what a reviewer needs.

---

## Caching

Verdicts are cached on disk, keyed by a SHA-256 digest of model, system prompt,
slice, schema and temperature.

The point is reproducibility more than cost. The project claims its results are
a property of the program analysis; a layer whose answers changed between two
runs over the same source would undermine that on the first re-run anyone
tried. Identical input yields the identical verdict; a changed slice — because
the code changed — correctly misses.

Entries are written through a temporary file and renamed, so concurrent audits
cannot leave a half-written entry behind. A corrupt or unreadable entry is
treated as a miss, never an error: a cache that can break a build is worse than
no cache.

```bash
prahari audit src/ --adjudicate --no-ai-cache    # bypass it
prahari ai                                        # where it lives
```

---

## Configuration

Three sources, lowest precedence first: a committed `prahari.toml`, a git-ignored
`.env` at the project root, then the real environment. See
[`.env.example`](../.env.example) and [`prahari.toml.example`](../prahari.toml.example).

`.env` is found by searching upward from the working directory, so the same file
serves the CLI run from `compiler/`, the benchmark, and the language server the
IDE spawns.

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` / `PRAHARI_API_KEY` / `ANTHROPIC_API_KEY` | — | credential; `.env` or environment, **never** `prahari.toml` |
| `PRAHARI_AI_PROVIDER` | detected from the key | `openrouter` or `anthropic` |
| `PRAHARI_MODEL` | per provider | `review` model id (`vendor/model:free` on OpenRouter) |
| `PRAHARI_MODEL_INTERACTIVE` | per provider | `interactive` model id, used by the IDE |
| `PRAHARI_MODEL_FALLBACKS` | per provider | comma-separated, tried in order |
| `PRAHARI_AI_FREE_ONLY` | `1` on OpenRouter | refuse any model id without `:free` |
| `PRAHARI_AI_REASONING` / `_INTERACTIVE` | `medium` / `low` | `none` · `minimal` · `low` · `medium` · `high` |
| `PRAHARI_AI_RPM` | `16` on OpenRouter | client-side pacing; `0` disables |
| `PRAHARI_API_BASE` | per provider | endpoint (a proxy, or the mock) |
| `PRAHARI_AI_MAX_REQUESTS` | `200` | hard per-run request ceiling |
| `PRAHARI_AI_RETRIES` | `3` | retries for retryable failures |
| `PRAHARI_AI_TIMEOUT` | `30` | seconds per request |
| `PRAHARI_AI_REQUIRE_TOOLS` | `0` | reject models that answer in prose |
| `PRAHARI_AI_CACHE` | `1` | on/off |
| `PRAHARI_AI_CACHE_DIR` | platform cache dir | where verdicts are stored |
| `PRAHARI_NO_DOTENV` | `0` | ignore `.env`; the test suite sets it |

An `api_key` written into `prahari.toml` is **deliberately ignored**, because that
file is the one that gets committed. `prahari ai` prints a 12-character
fingerprint of the key, never the key:

```console
$ prahari ai
adjudication configuration
  provider           anthropic
  model              claude-sonnet-5
  configured         True
  key_fingerprint    9b35edb491b3
  base_url           https://api.anthropic.com
  max_requests       200
  cache              ~/.cache/prahari/adjudication
  redact_paths       True
```

---

## Running on free models

Prahari is configured to cost nothing. With an OpenRouter key, **free-only mode is
on by default**: any model id that does not end in `:free` is refused before a
request is built — whether it came from `.env`, `prahari.toml` or `--model` — and
the refusal is reported with the offending id. A typo cannot become a bill.

### One model per use case

Prahari consults a model in two situations with opposite requirements:

| Use case | Where | Priority | Reasoning effort |
|---|---|---|---|
| `review` | `prahari audit --adjudicate`, CI | accuracy; nobody is waiting | `medium` |
| `interactive` | IDE *Review Findings with AI* | time to verdict; a developer is waiting | `low` |

Both share an ordered **fallback chain on different providers**, sent as
OpenRouter's `models` list. Free endpoints are congested and occasionally down;
when a fallback answers, the report names the model that did, so every verdict
stays attributable.

### Selection was two-stage, and the second stage changed the answer

**Stage 1 — published benchmarks** narrowed 22 free catalogue entries to models
with tool calling and strong independent results (Artificial Analysis
Intelligence Index v4.3, vendor model cards and release tables).

**Stage 2 — a live probe** sent every shortlisted model the exact request Prahari
sends: the adjudication system prompt, a forced `record_verdict` tool call.

| Model | Published evidence | Live probe (this key) |
|---|---|---|
| Inkling | AA 41, GPQA 87.2%, SWE-bench Verified 77.6% | **403 — free endpoint gated to listed agent apps** |
| Inkling Small | AA 40, GPQA 89% | **403 — same gate** |
| Laguna S 2.1 | Terminal-Bench 70.2%, SWE-bench Pro 59.4% | **429 — shared upstream free pool congested** |
| Gemma 4 31B / 26B | AA 15 (v4.3) | **429 — congested** |
| Nemotron 3 Ultra | AA 23 (v4.3), SWE-bench Verified 65–70% | tool call OK, 2.9 s |
| Nemotron 3 Super | AA 14 (v4.3) | tool call OK, 2.0 s — dominated by Ultra |
| Dots3-Note Preview | SWE-bench Verified 78.4% (vendor-reported) | tool call OK, 6.5 s |
| North Mini Code | SWE-bench Verified 67.6%, SWE-bench Pro 40.2% | tool call OK, 4.7 s |

The two strongest models on paper are unusable from a non-listed application,
and presenting Prahari as a listed app to get past the gate would be
impersonation, so they were dropped. Reachability is a selection criterion, not
an afterthought: a default that returns 429 is a default that silently does not
work.

**Stage 3 — this project's ground truth** decided among the reachable models.

### Stage 3 — the result

Run with `python eval/model_bench.py --yes`: a stratified sample of **7 real
findings and the 1 known false positive**, covering all seven weakness classes,
reviewed by each reachable model alone (no fallback) at `medium` effort.

| Model | F1 | Real bugs dismissed | False positives dismissed | Errors | Verdicts via tool | Median latency |
|---|---:|---:|---:|---:|---:|---:|
| *static — no model* | 0.933 | — | — | — | — | — |
| **Nemotron 3 Ultra** | **0.933** | **0** | 0 | **0** | **8/8** | 11.4 s |
| Dots3-Note Preview | 0.933 | 0 | 0 | 2 | 6/6 | 17.0 s |
| North Mini Code | 0.933 | 0 | 0 | 1 | 7/7 | 6.3 s |

**Read it honestly.** Every model agreed with the compiler on all seven real
bugs — none dismissed one, which is the failure that matters. None dismissed the
false positive either, so on this sample adjudication adds a reasoned second
opinion, not a precision gain. The benchmark's job was to find which model does
that *reliably*, and the answer was unambiguous: Nemotron 3 Ultra was the only
candidate to return a valid verdict for every finding. Dots3 answered twice
without calling the tool or emitting parseable JSON; North Mini Code ran out of
tokens mid-reasoning once.

### The defaults

| Role | Model | Reasoning effort | Why |
|---|---|---|---|
| `review` | `nvidia/nemotron-3-ultra-550b-a55b:free` | medium | only error-free run; strongest reachable model on independent benchmarks |
| `interactive` | `nvidia/nemotron-3-ultra-550b-a55b:free` | low | same reliable model, less thinking for time-to-verdict |
| fallback 1 | `cohere/north-mini-code:free` | — | different provider; fastest in the benchmark |
| fallback 2 | `dots-studio/dots-3-note-preview:free` | — | a third provider |

Fallbacks are on other providers deliberately: one provider's outage, or its
free pool filling up, cannot take out the whole chain.

These are defaults, not a lock-in. Free model availability changes weekly, which
is why the evidence is a re-runnable command rather than a paragraph:

```bash
prahari ai --models                  # what is free and reachable today
python eval/model_bench.py         # the plan and request count; spends nothing
python eval/model_bench.py --yes   # re-rank, then set PRAHARI_MODEL in .env
```

### Spending a daily quota carefully

OpenRouter allows free models **20 requests/minute**, and **50/day** on accounts
that have not purchased credits. Every retry is a request, so the gateway treats
the limit as a budget:

| Situation | Behaviour |
|---|---|
| Many findings at once | paced client-side at 16/min, so bursts never trip a 429 |
| `429` clearing within ~90 s | waited out once, honouring `Retry-After` / `X-RateLimit-Reset` |
| `429` resetting later (daily cap) | fails immediately with the reset time; later calls fail without a request |
| Upstream overload inside a `200` body | classified by `error.metadata.error_type`, retried as transient |
| Endpoint gated / refused by privacy policy | not retried; the error names the fix |
| Verdict already reviewed | served from the content-addressed cache, no request |

---

## Providers

| Key prefix | Provider | Endpoint | Default model |
|---|---|---|---|
| `sk-or-...` | OpenRouter | `https://openrouter.ai/api/v1/chat/completions` | `nvidia/nemotron-3-ultra-550b-a55b:free` |
| `sk-ant-...` | Anthropic | `https://api.anthropic.com/v1/messages` | `claude-sonnet-5` |

The provider is **detected from the key**, so pasting an OpenRouter key into
`.env` is the whole setup. Both gateways share one HTTP layer
(`ai/gateway/http.py`) for retries, backoff, budget and accounting; each adds
only its request builder and response parser.

OpenRouter differs in ways that matter and are handled explicitly: a `Bearer`
token, the system prompt as a message, the verdict as an OpenAI *function* tool
whose `arguments` arrive as a **JSON string**, errors that can arrive inside a
`200` body, and `402` for an account without credit (reported plainly, never
retried). Not every model on the platform supports tool calling; those answer
in prose, the gateway parses the JSON out of the content, and the benchmark
reports how many verdicts took each path. Set `PRAHARI_AI_REQUIRE_TOOLS=1` to
reject prose answers outright.

---

## Choosing a model

"Best" is measured against the evaluation's own ground truth, not asserted.

```bash
prahari ai --models                                  # what the key can reach, ranked
python eval/model_bench.py                         # the plan and its cost; spends nothing
python eval/model_bench.py --yes                   # run it
python eval/model_bench.py --models a/x b/y --yes  # specific candidates
```

Every finding on the two corpora is already labelled by the Juliet convention —
attributed to a `bad*` function it is real, to a `good*` function it is a false
positive. Adjudication can do exactly two things, and the benchmark scores both:
**dismissing a false positive** (the reason to use a model) and **dismissing a
real bug** (the thing that must not happen).

Ranking: F1 after adjudication, then fewest real bugs dismissed, then cost, then
latency. A `static` row — no model — is always included, and a model that scores
below it is reported as making the tool worse. Model ids are verified against
the live catalogue before anything is spent; missing ids are skipped with
same-vendor suggestions. Verdicts are cached per model, so a re-run is free and
reproduces the same table.

---

## No SDK

The request is one JSON POST, so it is made with the standard library. Adding
an HTTP client and its transitive dependencies to a compiler — whose analysis
core needs no network at all — is a cost with no matching benefit.

The transport is injectable, which is what makes the test suite hermetic.

---

## Testing without a credential

Two layers, because they catch different things.

**Injected transport** (`tests/test_ai.py` and `tests/test_openrouter.py`, 90 tests) covers gateway logic:
retries, status handling, budget, clamping, redaction, cache behaviour.

**Real HTTP** (`tests/test_ai_integration.py`, 10 tests) runs against
[`eval/mock_model.py`](../compiler/eval/mock_model.py), a deterministic endpoint
on a loopback port. The bytes go through `urllib_transport`, so header
construction, the POST, status handling and tool-use parsing are exercised as
one path — the parts most likely to break in deployment are exactly the parts an
injected transport cannot catch.

```bash
python eval/mock_model.py --port 8787 &
PRAHARI_API_KEY=mock PRAHARI_API_BASE=http://127.0.0.1:8787 \
    prahari audit examples --adjudicate
```

Its verdicts are a fixed rule, not a model: dismiss when a guard mentions a
length check, otherwise keep. That makes it useless as an oracle and ideal as a
fixture. **Nothing it produces is evidence about what a real model would say** —
which is precisely why the evaluation reports the `NullGateway` control row.

`--fail rate_limit|server_error|bad_key` makes it return errors instead, so the
degradation paths can be demonstrated rather than described.

---

## In the IDE

| Command | Effect |
|---|---|
| **Prahari: Audit Current File** (`Ctrl+Alt+A`) | local, free, no network |
| **Prahari: Review Findings with AI** | audits, then adjudicates |
| **Prahari: AI Adjudication Status** | model, endpoint, key fingerprint |

Kept separate on purpose: an audit is free and runs whenever asked, while
review costs a round trip per finding. That should be something a user chooses,
not something that happens to them.

The panel annotates rather than replaces. A dismissed finding is struck through
and faded — still present, still clickable, with the model's reasoning shown
beneath it. A tool that silently deletes results is one nobody can audit, and a
dismissal is a claim that deserves review like any other.

---

## What this is not

It is not a second detector. It cannot find a bug the compiler missed, by
construction — there is no code path from a response to a new finding.

It is not evidence in the evaluation. The ablation's last row is `NullGateway`,
the control: with no model configured its results are exactly the static
analysis's results, which is what makes it the correct baseline to measure any
future adjudicator against. Adding a row produced by a model would measure the
model and the analysis together, which is the confusion this whole design
exists to avoid.
