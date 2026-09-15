"""Verify that two audits of the same source produce the same report.

The claim this checks is precise: **the findings are a pure function of the
source revision and the specification table.** Nothing in the pipeline consults
a clock, a random seed, a network or an environment variable to decide what to
report, so two runs must agree.

Two fields are excluded, and naming them here rather than quietly diffing
around them is the point:

* ``elapsed_seconds`` -- wall-clock timing. Reporting it is useful; requiring it
  to be bit-identical would be requiring the machine to be idle.
* ``adjudication.elapsed_seconds`` -- the same, for the review pass.

Everything else is compared exactly, including the revision hash, every
finding, every path step, the ordering of findings, and the exclusion log. If a
non-determinism is ever introduced -- a set iterated without sorting, a
dictionary ordering leaking into output -- this fails and names the path to the
field that changed.

    python eval/check_determinism.py examples
    python eval/check_determinism.py --each eval/corpus

``--each`` audits every file in a directory *separately* and checks each one.
That is the stronger test: a corpus of independent programs audited as a single
translation unit is a degenerate input -- they redefine each other's functions,
which the type checker correctly reports as errors -- so comparing that tells
you little. Thirty independent audits compared pairwise tells you a great deal,
because any set iterated without sorting has thirty chances to show itself.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Fields allowed to differ between runs, as dotted paths. Every entry is a
#: measurement of the run rather than a statement about the program.
VOLATILE = frozenset({"stats.elapsed_seconds", "adjudication.elapsed_seconds"})


def audit(paths: list[str], extra: list[str] | None = None) -> dict:
    """Run the real CLI, the way a user or a CI job would."""
    command = [sys.executable, "-m", "aegis.cli", "audit", *paths, "--format", "json", *(extra or [])]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(ROOT),
        env={**_env(), "PYTHONIOENCODING": "utf-8"},
    )
    # Findings produce exit code 1 by design, which is not a failure here.
    if result.returncode not in (0, 1):
        raise SystemExit(f"audit failed ({result.returncode}):\n{result.stderr}")
    return json.loads(result.stdout)


def _env() -> dict:
    import os

    return {**os.environ, "PYTHONPATH": str(ROOT / "src")}


def strip(value, prefix: str = ""):
    """Remove volatile fields, recursively, preserving everything else."""
    if isinstance(value, dict):
        return {
            key: strip(item, f"{prefix}.{key}" if prefix else key)
            for key, item in value.items()
            if (f"{prefix}.{key}" if prefix else key) not in VOLATILE
        }
    if isinstance(value, list):
        return [strip(item, prefix) for item in value]
    return value


def differences(first, second, path: str = "") -> list[str]:
    """Every place the two reports disagree, as readable field paths."""
    if type(first) is not type(second):
        return [f"{path or '<root>'}: type changed {type(first).__name__} -> {type(second).__name__}"]

    if isinstance(first, dict):
        out: list[str] = []
        for key in sorted(set(first) | set(second)):
            where = f"{path}.{key}" if path else key
            if key not in first:
                out.append(f"{where}: appeared")
            elif key not in second:
                out.append(f"{where}: disappeared")
            else:
                out.extend(differences(first[key], second[key], where))
        return out

    if isinstance(first, list):
        if len(first) != len(second):
            return [f"{path}: length changed {len(first)} -> {len(second)}"]
        out = []
        for index, (a, b) in enumerate(zip(first, second)):
            out.extend(differences(a, b, f"{path}[{index}]"))
        return out

    return [] if first == second else [f"{path}: {first!r} -> {second!r}"]


def audit_in_process(path: str) -> dict:
    """The same pipeline without process startup, for the per-file sweep."""
    sys.path.insert(0, str(ROOT / "src"))
    from aegis.index import build_index

    index = build_index([path])
    return {
        "revision": index.revision,
        "findings": [
            {
                "ruleId": finding.rule_id,
                "cwe": finding.path.cwe,
                "severity": finding.severity.value,
                "function": finding.function,
                "fingerprint": finding.path.fingerprint,
                "steps": [
                    {"kind": s.kind, "line": s.location.line, "value": s.value}
                    for s in finding.path.steps
                ],
                "guards": [g.condition for g in finding.path.guards],
            }
            for finding in index.findings
        ],
        "exclusions": [e.as_dict() for e in index.exclusions],
        "diagnostics": [str(d) for d in index.diagnostics],
    }


def check_each(directory: str) -> int:
    """Audit every C file in ``directory`` twice, separately."""
    files = sorted(Path(directory).rglob("*.c"))
    if not files:
        print(f"no C files under {directory}", file=sys.stderr)
        return 2

    total_findings = 0
    for path in files:
        first, second = audit_in_process(str(path)), audit_in_process(str(path))
        failures = differences(first, second)
        if failures:
            print(f"OUTPUT IS NOT REPRODUCIBLE: {path}", file=sys.stderr)
            for failure in failures[:10]:
                print(f"  {failure}", file=sys.stderr)
            return 1
        total_findings += len(first["findings"])

    print(
        f"output is reproducible: {len(files)} files audited twice each, "
        f"{total_findings} findings identical"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--each":
        return check_each(argv[1] if len(argv) > 1 else "eval/corpus")

    paths = argv or ["examples"]
    first, second = strip(audit(paths)), strip(audit(paths))
    failures = differences(first, second)

    if failures:
        print("OUTPUT IS NOT REPRODUCIBLE", file=sys.stderr)
        for failure in failures[:25]:
            print(f"  {failure}", file=sys.stderr)
        if len(failures) > 25:
            print(f"  ... and {len(failures) - 25} more", file=sys.stderr)
        return 1

    print(
        f"output is reproducible: {len(first.get('findings', []))} findings identical "
        f"across two runs of {' '.join(paths)} "
        f"(revision {first.get('revision')}, ignoring {sorted(VOLATILE)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
