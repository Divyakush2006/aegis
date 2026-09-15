# Security policy

Aegis is a security tool, so it is held to the standard it applies to other
code. This page says how to report a vulnerability, what counts as one, and
which design decisions exist to keep the tool itself from becoming a risk.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub's
private vulnerability reporting: the repository's **Security** tab →
**Report a vulnerability**.

Include what you can of:

- the affected component (`compiler/`, the language server, `ide/`, CI);
- a minimal reproduction — for the compiler, the C input that triggers it;
- the impact you believe it has, and the version or commit.

We aim to acknowledge a report within seven days and will keep you informed
while a fix is prepared. Coordinated disclosure is appreciated.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## What is and is not a vulnerability

| In scope | Not a vulnerability |
|---|---|
| C input that makes Aegis execute code, write outside its output path, or hang indefinitely | A missed finding (false negative) or an extra one (false positive) — please open a normal issue with the C input; these are detection-quality bugs and are tracked in [docs/RESULTS.md](docs/RESULTS.md) |
| A credential appearing in any output, log, report, cache entry or error message | Constructs outside the documented C subset (see the README's *Scope*) |
| The IDE backend reachable from anything other than the local machine | Rate limiting or unavailability of third-party free model endpoints |
| An adjudication response able to create a finding, raise a confidence or change a severity | |

The last row is a security property, not only a design preference: the
invariants in [docs/AI.md](docs/AI.md) are what stop a manipulated model
response from altering what Aegis reports.

## Security-relevant design

**Credentials.** The API key is read only from the environment or a
git-ignored `.env`; a key written into the committed `aegis.toml` is refused.
Output shows a 12-character SHA-256 fingerprint, never the key. Tests assert
that no key appears in reports, `aegis ai` output, the IDE status command or
error messages, and CI fails if a mock credential leaks into any report.

**What leaves the machine.** Without a key, nothing does: the compiler, every
analysis and the IDE run offline. With a key, adjudication sends a *slice* of
each finding — the dataflow path, the relevant function summaries and the
guards on the path — with absolute directory paths removed. It never sends
whole files.

**Free model endpoints may retain prompts.** OpenRouter's free endpoints are
run by third-party providers whose data policies vary, and some free offerings
are provided in exchange for the right to log or train on inputs. Do not
adjudicate proprietary or confidential code on free endpoints without checking
the provider's policy and your OpenRouter privacy settings. The static analysis
never needs a model.

**No surprise spending.** With OpenRouter, free-only mode refuses any model id
that does not end in `:free` before a request is built.

**Model output is untrusted input.** Verdicts are requested through a forced
tool call with a JSON schema, clamped, and applied only through the
demote-only invariants. A malformed or hostile response is recorded as an
error and the compiler's own verdict stands.

**Supply chain.** `ide/.npmrc` sets `ignore-scripts=true`, so no dependency
install script runs arbitrary code at install time. The Python package's core
has two runtime dependencies (`pycparser`, `networkx`); the model gateways use
the standard library only.

**Local-only services.** The IDE listens on `127.0.0.1`. The language server
communicates with the IDE over stdio and opens no network port.
