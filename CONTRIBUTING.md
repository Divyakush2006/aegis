# Contributing to Prahari

Thank you for improving Prahari. This guide covers setting up, checking your
change, and the handful of properties every change has to preserve.

## Layout

```
compiler/   Python — front end, IR, SSA, dataflow analyses, detectors,
            SARIF, LLVM codegen, language server, AI gateways, evaluation
ide/        TypeScript — the Eclipse Theia application and the Prahari extension
docs/       architecture, results, AI design, attribution, planning record
```

## Setting up

```bash
# the compiler
cd compiler
pip install -e ".[dev,codegen,lsp]"

# the IDE (no C++ toolchain needed on any platform)
cd ide
npm install
npm run build
npm start                     # http://127.0.0.1:3000
```

If the `prahari` command is not on your PATH after installing, use
`python -m prahari.cli` instead; pip installs console scripts into a per-user
directory that is not always on PATH.

AI review is optional. To enable it, copy `.env.example` to `.env` at the
project root and set `OPENROUTER_API_KEY`. Nothing below requires a key.

## Checking a change

Run what your change touches; CI runs all of it.

| Check | Command (from `compiler/` unless noted) |
|---|---|
| Unit and integration tests | `python -m pytest` |
| Lint | `ruff check src eval tests --select F,E4,E7,E9` |
| Detection rate and false positive rate | `python eval/harness.py` and `python eval/harness.py eval/corpus_hard` |
| Ablation matrix | `python eval/ablation.py` |
| Reproducible output | `python eval/check_determinism.py examples` and `--each eval/corpus` |
| Model benchmark, offline | `python eval/model_bench.py --mock --yes` |
| IDE typecheck and bundle | `npx tsc -p prahari-ide/tsconfig.json` and `npm run build` (from `ide/`) |
| IDE ↔ compiler end to end | `node e2e-check.js` (from `ide/`) |
| The IDE in a real browser | `npm start`, then `node browser-check.js` (from `ide/`; needs Chrome, Chromium or Edge) |

The test suite never makes a network call or reads a developer's `.env`:
`tests/conftest.py` switches both off, and model tests run against an injected
transport or the local mock endpoint in `eval/mock_model.py`.

## Properties every change must preserve

These are enforced by tests and CI. A change that needs to break one needs an
explicit discussion first, because the project's published claims depend on
them.

1. **Adjudication can only demote.** A model response can never create a
   finding, raise a confidence, or change a severity (`TestInvariants` in
   `tests/test_ai.py`, and `eval/check_invariants.py` on the reports).
2. **The static pipeline is deterministic.** Two audits of the same source
   produce the same report, apart from named timing fields
   (`eval/check_determinism.py`).
3. **An unconfigured install is a working install.** No key, a refused model or
   an unreachable endpoint degrades to the compiler's own verdicts; it never
   fails an audit.
4. **Free-only is the default with OpenRouter.** A default model id must end in
   `:free` (`tests/test_free_tier.py`). Changing a default requires re-running
   `python eval/model_bench.py` and updating the evidence in `docs/AI.md`.
5. **No credential in any output.** Reports, logs, errors and status commands
   show a fingerprint only.
6. **Published numbers stay true.** If a change moves the detection rate, false
   positive rate or ablation matrix, update `docs/RESULTS.md` and the README in
   the same change. `tests/test_eval.py` fails when they drift.

## Style

- Python: `ruff` with a line length of 100; type hints on public functions.
- TypeScript: the existing four-space style; `tsc` must report zero errors.
- Comments and docstrings explain *why* a decision was made — the constraint,
  the trade-off, the failure it prevents — rather than restating the code.
- A new weakness class is a detector module, a specification entry, corpus
  cases for both the flawed and the safe variant, and a row in the results.

## Commits and pull requests

Keep a change focused on one concern, describe what it changes and why, and
include the relevant check output in the pull request. Record user-visible
changes in [CHANGELOG.md](CHANGELOG.md).

Report security issues privately — see [SECURITY.md](SECURITY.md).
